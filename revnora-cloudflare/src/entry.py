import json, os, hmac, hashlib, time, secrets
from urllib.parse import urlparse, parse_qsl, parse_qs
from workers import WorkerEntrypoint, Response
from js import fetch, JSON

ORIGIN = "https://revnora.charvisharma7619.workers.dev"

def reply(data, status=200):
    return Response.json(data, status=status, headers={
        "Access-Control-Allow-Origin": ORIGIN,
        "Access-Control-Allow-Headers": "Content-Type, X-Telegram-Init-Data, X-Admin-Key",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
    })


async def telegram_post(url, payload):
    # Convert request options into a native JavaScript object before calling fetch.
    options = JSON.parse(json.dumps({
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(payload)
    }))
    return await fetch(url, options)

def verify(init_data, token):
    if not init_data or not token: return None
    try:
        values = dict(parse_qsl(init_data, keep_blank_values=True))
        received = values.pop("hash", None)
        if not received: return None
        check = "\n".join(f"{k}={v}" for k, v in sorted(values.items()))
        secret = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
        expected = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, received): return None
        stamp = int(values.get("auth_date", "0"))
        if stamp > int(time.time()) or int(time.time()) - stamp > 86400: return None
        user = json.loads(values["user"])
        return user if user.get("id") else None
    except Exception: return None

class Default(WorkerEntrypoint):
    async def fetch(self, request):
        if request.method == "OPTIONS":
            return Response("", status=204, headers={
                "Access-Control-Allow-Origin": ORIGIN,
                "Access-Control-Allow-Headers": "Content-Type, X-Telegram-Init-Data, X-Admin-Key",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS"})
        path = urlparse(request.url).path.rstrip("/") or "/"
        method = request.method
        db = self.env.DB

        async def data():
            try: return await request.json()
            except Exception: return {}
        async def first(sql, *args):
            return await db.prepare(sql).bind(*args).first()
        async def rows(sql, *args):
            result = await db.prepare(sql).bind(*args).all()
            return result.results or []
        async def execute(sql, *args):
            return await db.prepare(sql).bind(*args).run()
        async def user_auth(body=None, route_id=None):
            user = verify(request.headers.get("X-Telegram-Init-Data", ""), getattr(self.env, "BOT_TOKEN", None))
            if not user: return None, reply({"status":"error","message":"Invalid or expired Telegram login"},401)
            uid = int(user["id"])
            requested = route_id if route_id is not None else (body or {}).get("telegram_id")
            if requested is not None:
                try:
                    if int(requested) != uid: return None, reply({"status":"error","message":"Telegram account mismatch"},403)
                except Exception: return None, reply({"status":"error","message":"Invalid telegram_id"},400)
            return user, None
        def admin_check():
            try:
                key = str(getattr(self.env, "ADMIN_API_KEY", None) or "").strip()
                supplied = str(request.headers.get("X-Admin-Key", "") or "").strip()
                return bool(key and supplied and key == supplied), bool(key), bool(supplied)
            except Exception:
                return False, False, False

        def is_admin():
            return admin_check()[0]

        if path == "/telegram-webhook" and method == "POST":
            secret = str(getattr(self.env, "ADMIN_API_KEY", None) or "").strip()
            supplied = str(request.headers.get("X-Telegram-Bot-Api-Secret-Token", "") or "").strip()
            if not secret or not supplied or secret != supplied:
                return reply({"ok":False,"message":"Unauthorized"}, 401)
            update = await data()
            message = update.get("message") or update.get("edited_message") or {}
            chat = message.get("chat") or {}
            if message.get("text", "").split(" ", 1)[0] == "/start" and chat.get("id"):
                token = getattr(self.env, "BOT_TOKEN", None)
                if not token:
                    return reply({"ok":False,"message":"Bot token is not configured"}, 500)
                payload = {
                    "chat_id": chat["id"],
                    "text": "Welcome to REVNORA! 🎮\\nEarn rewards by completing tasks, claiming daily bonuses and inviting friends.",
                    "reply_markup": {"inline_keyboard": [[{
                        "text": "🚀 Open REVNORA",
                        "web_app": {"url": "https://revnora.charvisharma7619.workers.dev"}
                    }]]}
                }
                result = await telegram_post(
                    "https://api.telegram.org/bot" + str(token) + "/sendMessage", payload
                )
                if not result.ok:
                    return reply({"ok":False,"message":"Telegram sendMessage failed"}, 502)
            return reply({"ok":True})

        if path == "/api/admin/telegram-webhook-info" and method == "GET":
            try:
                if not admin_check()[0]:
                    return reply({"status":"error","message":"Unauthorized"},401)
                token = str(getattr(self.env, "BOT_TOKEN", None) or "").strip()
                if not token:
                    return reply({"status":"error","message":"Bot token is not configured"},500)
                result = await fetch("https://api.telegram.org/bot" + token + "/getWebhookInfo")
                info = json.loads(await result.text())
                return reply({"status":"success","webhook":info},200)
            except Exception as exc:
                return reply({"status":"error","diagnostic_type":type(exc).__name__,
                              "diagnostic_message":str(exc)[:300]},500)

        if path == "/api/admin/telegram-webhook" and method == "POST":
            # Keep the whole admin setup route guarded: a runtime exception must
            # return JSON diagnostics rather than crashing the Worker with 1101.
            try:
                admin_ok, key_configured, header_received = admin_check()
                if not admin_ok:
                    return reply({"status":"error","message":"Unauthorized",
                                  "diagnostics":{"admin_key_configured":key_configured,
                                                 "admin_header_received":header_received}}, 401)
                token = str(getattr(self.env, "BOT_TOKEN", None) or "").strip()
                secret = str(getattr(self.env, "ADMIN_API_KEY", None) or "").strip()
                if not token or not secret:
                    return reply({"status":"error","message":"Bot configuration is missing"}, 500)
                result = await telegram_post(
                    "https://api.telegram.org/bot" + token + "/setWebhook",
                    {
                        "url":"https://revnora-backend.charvisharma7619.workers.dev/telegram-webhook",
                        "secret_token":secret,
                        "allowed_updates":["message"]
                    }
                )
                telegram_result = json.loads(await result.text())
                return reply({"status":"success" if telegram_result.get("ok") else "error",
                              "telegram":telegram_result}, 200 if telegram_result.get("ok") else 502)
            except Exception as exc:
                return reply({"status":"error","diagnostic_type":type(exc).__name__,
                              "diagnostic_message":str(exc)[:300]}, 500)

        if path == "/":
            return reply({"ok":True,"service":"revnora-backend","status":"deployed"})
        if path == "/api/db-check":
            return reply({"ok":True,"database":"connected","result":await first("SELECT 1 AS ok")})
        if path == "/api/auth" and method == "POST":
            u = verify(request.headers.get("X-Telegram-Init-Data",""),getattr(self.env,"BOT_TOKEN",None))
            if not u: return reply({"status":"error","message":"Invalid or expired Telegram login"},401)
            return reply({"status":"success","user":{"id":u.get("id"),"first_name":u.get("first_name",""),"username":u.get("username","")}})

        if path == "/api/offerwall/url" and method == "POST":
            u,err=await user_auth(await data())
            if err: return err
            public=str(getattr(self.env,"OFFERWALL_PUBLIC_KEY",None) or "").strip()
            secret=str(getattr(self.env,"OFFERWALL_SECRET_KEY",None) or "").strip()
            if not public or not secret:
                return reply({"status":"error","message":"Offerwall credentials are not configured"},503)
            uid=str(int(u["id"]))
            expires=str(int(time.time())+3600)
            message="offerwall-user-v1\n"+public+"\n"+uid+"\n"+expires
            signature=hmac.new(secret.encode(),message.encode(),hashlib.sha256).hexdigest()
            from urllib.parse import quote
            wall="https://offerwall.me/offerwall/"+quote(public,safe="")+"/"+quote(uid,safe="")
            wall+="?identityExpires="+expires+"&identitySignature="+signature
            return reply({"status":"success","url":wall})

        if path == "/api/offerwall/postback" and method == "POST":
            try:
                raw=await request.text()
                params=dict(parse_qsl(raw,keep_blank_values=True))
                if not params:
                    try: params=await request.json()
                    except Exception: params={}
                get=lambda k: str(params.get(k,""))
                sub_id,trans_id,reward,sig=get("subId"),get("transId"),get("reward"),get("signature")
                secret=str(getattr(self.env,"OFFERWALL_SECRET_KEY",None) or "").strip()
                if not secret or not all((sub_id,trans_id,reward,sig)):
                    return Response("invalid",status=400)
                expected=hashlib.md5((sub_id+trans_id+reward+secret).encode()).hexdigest()
                if not hmac.compare_digest(expected.lower(),sig.lower()):
                    return Response("invalid signature",status=403)
                try:
                    uid=int(sub_id)
                    from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
                    reward_value=Decimal(reward)
                    coins=int(reward_value.quantize(Decimal("1"),rounding=ROUND_HALF_UP))
                except Exception:
                    return Response("invalid reward or user",status=400)
                if uid<=0 or coins<=0 or len(trans_id)>180:
                    return Response("invalid values",status=400)
                user=await first("SELECT telegram_id FROM users WHERE telegram_id=?",uid)
                if not user: return Response("unknown user",status=404)
                status=get("status")
                if status not in ("1","2"): return Response("invalid status",status=400)
                await execute("""CREATE TABLE IF NOT EXISTS offerwall_transactions (
                    trans_id TEXT PRIMARY KEY, telegram_id INTEGER NOT NULL, offer_name TEXT,
                    offer_type TEXT, reward_text TEXT NOT NULL, coins INTEGER NOT NULL,
                    payout_usd TEXT, country TEXT, status TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )""")
                if status=="1":
                    await db.batch([
                        db.prepare("""INSERT OR IGNORE INTO offerwall_transactions
                            (trans_id,telegram_id,offer_name,offer_type,reward_text,coins,payout_usd,country,status)
                            VALUES(?,?,?,?,?,?,?,?, 'approved')""").bind(trans_id,uid,get("offer_name"),get("offer_type"),reward,coins,get("payout"),get("country")),
                        db.prepare("""UPDATE users SET coins=coins+? WHERE telegram_id=?
                            AND changes()=1 AND EXISTS(SELECT 1 FROM offerwall_transactions WHERE trans_id=? AND status='approved')""").bind(coins,uid,trans_id),
                        db.prepare("""INSERT INTO transactions(telegram_id,amount,transaction_type,description)
                            SELECT ?,?,'offerwall_reward',? WHERE changes()=1""").bind(uid,coins,"Offerwall: "+(get("offer_name") or get("offer_type") or "Reward")),
                    ])
                else:
                    await db.batch([
                        db.prepare("""UPDATE offerwall_transactions SET status='reversed',updated_at=CURRENT_TIMESTAMP
                            WHERE trans_id=? AND telegram_id=? AND status='approved'""").bind(trans_id,uid),
                        db.prepare("""UPDATE users SET coins=coins-? WHERE telegram_id=?
                            AND changes()=1""").bind(coins,uid),
                        db.prepare("""INSERT INTO transactions(telegram_id,amount,transaction_type,description)
                            SELECT ?,?,'offerwall_reversal',? WHERE changes()=1""").bind(uid,-coins,"Offerwall reversal: "+trans_id),
                    ])
                return Response("ok",status=200)
            except Exception as exc:
                return Response("postback error",status=500)

        if path == "/api/ads/start" and method == "POST":
            u,err=await user_auth(await data())
            if err: return err
            uid=int(u["id"])
            await execute("""CREATE TABLE IF NOT EXISTS monetag_ad_sessions (
                ymid TEXT PRIMARY KEY, telegram_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', zone_id TEXT,
                event_type TEXT, reward_event_type TEXT,
                estimated_price REAL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                confirmed_at TEXT
            )""")
            ymid="rv"+str(uid)+"_"+secrets.token_hex(12)
            await execute("INSERT INTO monetag_ad_sessions(ymid,telegram_id) VALUES(?,?)",ymid,uid)
            return reply({"status":"success","ymid":ymid,"message":"Ad session created"})

        if path == "/api/monetag/postback" and method == "GET":
            try:
                params=parse_qs(urlparse(request.url).query,keep_blank_values=True)
                get=lambda k: (params.get(k) or [""])[0]
                await execute("""CREATE TABLE IF NOT EXISTS monetag_postback_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ymid TEXT, zone_id TEXT,
                    event_type TEXT, reward_event_type TEXT, estimated_price TEXT,
                    outcome TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )""")
                secret=str(getattr(self.env,"MONETAG_POSTBACK_SECRET",None) or "").strip()
                supplied=get("key")
                key_ok=bool(secret and supplied and hmac.compare_digest(secret,supplied))
                ymid=get("ymid")
                zone=get("zone_id")
                event=get("event_type")
                reward=get("reward_event_type")
                price_text=get("estimated_price")
                if not key_ok:
                    await execute("INSERT INTO monetag_postback_logs(ymid,zone_id,event_type,reward_event_type,estimated_price,outcome) VALUES(?,?,?,?,?,?)",ymid,zone,event,reward,price_text,"unauthorized_key")
                    return reply({"status":"error","message":"Unauthorized"},401)
                if not ymid or len(ymid)>120 or zone!="12170892":
                    await execute("INSERT INTO monetag_postback_logs(ymid,zone_id,event_type,reward_event_type,estimated_price,outcome) VALUES(?,?,?,?,?,?)",ymid,zone,event,reward,price_text,"invalid_ymid_or_zone")
                    return reply({"status":"ignored","reason":"Invalid ymid or zone"},400)
                # Monetag can report both impression and click events for a
                # Rewarded Interstitial. Accept either only when Monetag marks
                # the event as monetized; the ymid row makes processing idempotent.
                if event not in ("impression","click") or reward!="valued":
                    await execute("INSERT INTO monetag_postback_logs(ymid,zone_id,event_type,reward_event_type,estimated_price,outcome) VALUES(?,?,?,?,?,?)",ymid,zone,event,reward,price_text,"not_valued_or_unsupported_event")
                    return reply({"status":"ignored","reason":"Event is not monetized"})
                await execute("""CREATE TABLE IF NOT EXISTS monetag_ad_sessions (
                    ymid TEXT PRIMARY KEY, telegram_id INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending', zone_id TEXT,
                    event_type TEXT, reward_event_type TEXT,
                    estimated_price REAL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    confirmed_at TEXT
                )""")
                session=await first("SELECT telegram_id,status FROM monetag_ad_sessions WHERE ymid=?",ymid)
                if not session:
                    await execute("INSERT INTO monetag_postback_logs(ymid,zone_id,event_type,reward_event_type,estimated_price,outcome) VALUES(?,?,?,?,?,?)",ymid,zone,event,reward,price_text,"unknown_ymid")
                    return reply({"status":"ignored","reason":"Unknown ad session"},404)
                if session["status"]!="pending":
                    return reply({"status":"success","duplicate":True,"message":"Already processed","coins_credited":0})
                try: price=max(0.0,float(get("estimated_price") or 0))
                except Exception: price=0.0
                # One unique reward ledger row per ymid prevents duplicate postbacks
                # from crediting the same ad more than once.
                await execute("""CREATE TABLE IF NOT EXISTS monetag_rewards (
                    ymid TEXT PRIMARY KEY, telegram_id INTEGER NOT NULL,
                    coins INTEGER NOT NULL DEFAULT 10, credited INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )""")
                await db.batch([
                    db.prepare("""INSERT OR IGNORE INTO monetag_rewards(ymid,telegram_id,coins,credited)
                        SELECT s.ymid,s.telegram_id,10,0 FROM monetag_ad_sessions s
                        JOIN users u ON u.telegram_id=s.telegram_id
                        WHERE s.ymid=? AND s.status='pending'""").bind(ymid),
                    db.prepare("""UPDATE users SET coins=coins+10 WHERE telegram_id=(
                        SELECT telegram_id FROM monetag_rewards WHERE ymid=? AND credited=0)""").bind(ymid),
                    db.prepare("""INSERT INTO transactions(telegram_id,amount,transaction_type,description)
                        SELECT telegram_id,10,'monetag_reward','Monetag valued ad reward'
                        FROM monetag_rewards WHERE ymid=? AND credited=0""").bind(ymid),
                    db.prepare("UPDATE monetag_rewards SET credited=1 WHERE ymid=? AND credited=0").bind(ymid),
                    db.prepare("""UPDATE monetag_ad_sessions SET status='valued',
                        zone_id=?,event_type=?,reward_event_type=?,estimated_price=?,
                        confirmed_at=CURRENT_TIMESTAMP WHERE ymid=? AND status='pending'
                        AND EXISTS (SELECT 1 FROM monetag_rewards WHERE ymid=? AND credited=1)""").bind(zone,event,reward,price,ymid,ymid)
                ])
                await execute("INSERT INTO monetag_postback_logs(ymid,zone_id,event_type,reward_event_type,estimated_price,outcome) VALUES(?,?,?,?,?,?)",ymid,zone,event,reward,price_text,"valued_recorded")
                return reply({"status":"success","recorded":True,"coins_credited":10})
            except Exception as exc:
                return reply({"status":"error","diagnostic_type":type(exc).__name__,
                              "diagnostic_message":str(exc)[:200]},500)

        if path.startswith("/api/ads/status/") and method == "GET":
            ymid=path.rsplit("/",1)[1]
            u,err=await user_auth()
            if err: return err
            session=await first("SELECT status,estimated_price FROM monetag_ad_sessions WHERE ymid=? AND telegram_id=?",ymid,int(u["id"]))
            if not session: return reply({"status":"error","message":"Ad session not found"},404)
            return reply({"status":"success","ad_status":session["status"],"estimated_price":session["estimated_price"]})

        if path.startswith("/api/admin/"):
            if not is_admin(): return reply({"status":"error","message":"Unauthorized"},401)
            if path == "/api/admin/monetag-events" and method == "GET":
                result=await rows("SELECT l.id,l.ymid,s.telegram_id,l.zone_id,l.event_type,l.reward_event_type,l.estimated_price,l.outcome,l.created_at FROM monetag_postback_logs l LEFT JOIN monetag_ad_sessions s ON s.ymid=l.ymid ORDER BY l.id DESC LIMIT 30")
                return reply({"status":"success","events":result})
            if path == "/api/admin/users" and method == "GET":
                result=await rows("SELECT telegram_id,username,first_name,coins,referral_code,referred_by,created_at FROM users ORDER BY created_at DESC")
                return reply({"status":"success","total_users":len(result),"users":result})
            if path == "/api/admin/tasks" and method == "POST":
                d=await data()
                try: reward=int(d.get("reward_coins"))
                except Exception: return reply({"status":"error","message":"Invalid reward"},400)
                if not d.get("title") or not d.get("task_type") or reward<=0: return reply({"status":"error","message":"Invalid task details"},400)
                result=await execute("INSERT INTO tasks(title,description,task_type,reward_coins,target_url) VALUES(?,?,?,?,?)",d["title"],d.get("description",""),d["task_type"],reward,d.get("target_url",""))
                return reply({"status":"success","message":"Task created successfully","task_id":result.meta.last_row_id},201)
            if path == "/api/admin/withdrawals" and method == "GET":
                await execute("""CREATE TABLE IF NOT EXISTS withdrawal_currency_details (
                    withdrawal_id INTEGER PRIMARY KEY, country_code TEXT, currency TEXT NOT NULL,
                    payout_amount REAL NOT NULL, coins INTEGER NOT NULL
                )""")
                result=await rows("""SELECT w.id,w.telegram_id,w.amount,w.payment_method,w.payment_details,w.status,w.created_at,
                    d.country_code,d.currency,d.payout_amount FROM withdrawals w
                    LEFT JOIN withdrawal_currency_details d ON d.withdrawal_id=w.id
                    ORDER BY w.created_at DESC""")
                return reply({"status":"success","total_withdrawals":len(result),"withdrawals":result})
            if path == "/api/admin/coins" and method == "POST":
                d=await data()
                try: uid,amount=int(d.get("telegram_id")),int(d.get("amount"))
                except Exception: return reply({"status":"error","message":"Valid telegram_id and amount are required"},400)
                if amount==0: return reply({"status":"error","message":"Amount cannot be zero"},400)
                u=await first("SELECT coins FROM users WHERE telegram_id=?",uid)
                if not u: return reply({"status":"error","message":"User not found"},404)
                if u["coins"]+amount<0: return reply({"status":"error","message":"Balance cannot become negative"},400)
                await db.batch([
                    db.prepare("UPDATE users SET coins=coins+? WHERE telegram_id=?").bind(amount,uid),
                    db.prepare("INSERT INTO transactions(telegram_id,amount,transaction_type,description) VALUES(?,?,?,?)").bind(uid,amount,"admin_credit" if amount>0 else "admin_debit",str(d.get("description","Admin coin adjustment")))
                ])
                updated=await first("SELECT coins FROM users WHERE telegram_id=?",uid)
                return reply({"status":"success","message":"User coins updated successfully","telegram_id":uid,"adjustment":amount,"new_balance":updated["coins"]})
            if path.startswith("/api/admin/withdrawals/") and method == "POST":
                try: wid=int(path.rsplit("/",1)[1])
                except Exception: return reply({"status":"error","message":"Invalid withdrawal id"},400)
                d=await data(); action=d.get("action")
                if action not in ("approve","reject"): return reply({"status":"error","message":"Invalid action"},400)
                w=await first("SELECT * FROM withdrawals WHERE id=?",wid)
                if not w: return reply({"status":"error","message":"Withdrawal not found"},404)
                if w["status"]!="pending": return reply({"status":"error","message":"Already processed"},400)
                if action=="approve":
                    u=await first("SELECT coins FROM users WHERE telegram_id=?",w["telegram_id"])
                    if not u or u["coins"]<w["amount"]: return reply({"status":"error","message":"Insufficient balance"},400)
                    await db.batch([
                        db.prepare("UPDATE users SET coins=coins-? WHERE telegram_id=? AND coins>=?").bind(w["amount"],w["telegram_id"],w["amount"]),
                        db.prepare("INSERT INTO transactions(telegram_id,amount,transaction_type,description) VALUES(?,?,?,?)").bind(w["telegram_id"],-w["amount"],"withdrawal","Withdrawal approved"),
                        db.prepare("UPDATE withdrawals SET status='approved' WHERE id=? AND status='pending'").bind(wid)
                    ])
                    status="approved"
                else:
                    await execute("UPDATE withdrawals SET status='rejected' WHERE id=? AND status='pending'",wid)
                    status="rejected"
                return reply({"status":"success","message":"Withdrawal "+status,"withdrawal_id":wid})
            return reply({"status":"error","message":"Not found"},404)

        if path == "/api/tasks" and method == "GET":
            result=await rows("SELECT id,title,description,task_type,reward_coins,target_url FROM tasks WHERE status='active'")
            return reply({"status":"success","total_tasks":len(result),"tasks":result})
        if path == "/api/register" and method == "POST":
            d=await data(); u,err=await user_auth(d)
            if err: return err
            uid=int(u["id"]); old=await first("SELECT referral_code FROM users WHERE telegram_id=?",uid)
            if old: return reply({"status":"success","message":"User already registered","referral_code":old["referral_code"]})
            ref=None
            if d.get("referral_code"):
                ref=await first("SELECT telegram_id FROM users WHERE referral_code=?",str(d["referral_code"]).strip().upper())
                if not ref: return reply({"status":"error","message":"Invalid referral code"},400)
                if int(ref["telegram_id"])==uid: return reply({"status":"error","message":"Self referral not allowed"},400)
            code=secrets.token_hex(4).upper()
            await execute("INSERT INTO users(telegram_id,username,first_name,referral_code,referred_by) VALUES(?,?,?,?,?)",uid,u.get("username",d.get("username","")),u.get("first_name",d.get("first_name","")),code,ref["telegram_id"] if ref else None)
            return reply({"status":"success","message":"User registered successfully","referral_code":code},201)

        if path.startswith(("/api/balance/","/api/transactions/","/api/referral/","/api/daily/")):
            try: uid=int(path.rsplit("/",1)[1])
            except Exception: return reply({"status":"error","message":"Invalid telegram_id"},400)
            d=await data() if method=="POST" else {}
            u,err=await user_auth(d,uid)
            if err: return err
            if path.startswith("/api/balance/"):
                urow=await first("SELECT coins FROM users WHERE telegram_id=?",uid)
                if not urow: return reply({"status":"error","message":"User not found"},404)
                return reply({"status":"success","telegram_id":uid,"coins":urow["coins"]})
            if path.startswith("/api/transactions/"):
                result=await rows("SELECT amount,transaction_type,description,created_at FROM transactions WHERE telegram_id=? ORDER BY id DESC",uid)
                return reply({"status":"success","telegram_id":uid,"transactions":result})
            if path.startswith("/api/referral/"):
                urow=await first("SELECT referral_code FROM users WHERE telegram_id=?",uid)
                if not urow: return reply({"status":"error","message":"User not found"},404)
                count=await first("SELECT COUNT(*) AS total_referrals FROM users WHERE referred_by=?",uid)
                return reply({"status":"success","telegram_id":uid,"referral_code":urow["referral_code"],"total_referrals":count["total_referrals"]})
            if path.startswith("/api/daily/") and method=="POST":
                claimed=await first("SELECT id FROM transactions WHERE telegram_id=? AND transaction_type='daily_bonus' AND date(created_at,'+5 hours','+30 minutes')=date('now','+5 hours','+30 minutes')",uid)
                if claimed: return reply({"status":"error","message":"Daily bonus already claimed today"},400)
                user=await first("SELECT coins FROM users WHERE telegram_id=?",uid)
                if not user: return reply({"status":"error","message":"User not found"},404)
                await db.batch([
                    db.prepare("UPDATE users SET coins=coins+10 WHERE telegram_id=?").bind(uid),
                    db.prepare("INSERT INTO transactions(telegram_id,amount,transaction_type,description) VALUES(?,?,?,?)").bind(uid,10,"daily_bonus","Daily bonus claimed")
                ])
                return reply({"status":"success","message":"Daily bonus claimed successfully","reward":10})
        if path == "/api/withdraw" and method == "POST":
            d=await data(); u,err=await user_auth(d)
            if err: return err
            try: uid,amount=int(u["id"]),int(d.get("amount"))
            except Exception: return reply({"status":"error","message":"Valid details required"},400)
            pm,pd=d.get("payment_method"),d.get("payment_details")
            if amount<=0 or not pm or not pd: return reply({"status":"error","message":"Invalid withdrawal details"},400)
            user=await first("SELECT coins FROM users WHERE telegram_id=?",uid)
            if not user: return reply({"status":"error","message":"User not found"},404)
            if user["coins"]<amount: return reply({"status":"error","message":"Insufficient coin balance"},400)
            # Determine payout currency from Cloudflare's country signal, not Telegram language.
            country=str(request.headers.get("CF-IPCountry","") or "").upper()
            currency="INR" if country=="IN" else "USD"
            payout_amount=round(amount/20,2) if currency=="INR" else round(amount/1000,2)
            await execute("INSERT INTO withdrawals(telegram_id,amount,payment_method,payment_details) VALUES(?,?,?,?)",uid,amount,pm,pd)
            withdrawal=await first("SELECT id FROM withdrawals WHERE telegram_id=? ORDER BY id DESC LIMIT 1",uid)
            await execute("""CREATE TABLE IF NOT EXISTS withdrawal_currency_details (
                withdrawal_id INTEGER PRIMARY KEY, country_code TEXT, currency TEXT NOT NULL,
                payout_amount REAL NOT NULL, coins INTEGER NOT NULL
            )""")
            await execute("INSERT OR REPLACE INTO withdrawal_currency_details(withdrawal_id,country_code,currency,payout_amount,coins) VALUES(?,?,?,?,?)",
                withdrawal["id"],country,currency,payout_amount,amount)
            return reply({"status":"success","message":"Withdrawal request submitted","currency":currency,
                          "payout_amount":payout_amount,"coins":amount,"country_code":country},201)
        return reply({"status":"error","message":"Not found"},404)
