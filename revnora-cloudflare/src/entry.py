import json, os, hmac, hashlib, time, secrets
from urllib.parse import urlparse, parse_qsl
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

        if path.startswith("/api/admin/"):
            if not is_admin(): return reply({"status":"error","message":"Unauthorized"},401)
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
                result=await rows("SELECT id,telegram_id,amount,payment_method,payment_details,status,created_at FROM withdrawals ORDER BY created_at DESC")
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
            await execute("INSERT INTO withdrawals(telegram_id,amount,payment_method,payment_details) VALUES(?,?,?,?)",uid,amount,pm,pd)
            return reply({"status":"success","message":"Withdrawal request submitted"},201)
        return reply({"status":"error","message":"Not found"},404)
