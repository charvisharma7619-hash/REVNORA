
from flask import Flask, jsonify, request, g
from database import get_connection
from dotenv import load_dotenv
from functools import wraps
import secrets
import os
from telegram_auth import verify_telegram_init_data

load_dotenv()
app = Flask(__name__)


# TELEGRAM MINI APP AUTHENTICATION
def telegram_user_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        init_data = request.headers.get("X-Telegram-Init-Data", "")
        telegram_user = verify_telegram_init_data(init_data)

        if not telegram_user:
            return jsonify({
                "status": "error",
                "message": "Invalid or expired Telegram login"
            }), 401

        try:
            verified_id = int(telegram_user.get("id"))
        except (TypeError, ValueError):
            return jsonify({"status": "error", "message": "Invalid Telegram user"}), 401

        requested_id = kwargs.get("telegram_id")
        if requested_id is None:
            body = request.get_json(silent=True) or {}
            requested_id = body.get("telegram_id")

        if requested_id is not None:
            try:
                if int(requested_id) != verified_id:
                    return jsonify({
                        "status": "error",
                        "message": "Telegram account mismatch"
                    }), 403
            except (TypeError, ValueError):
                return jsonify({"status": "error", "message": "Invalid telegram_id"}), 400

        g.telegram_user = telegram_user
        return func(*args, **kwargs)
    return wrapper


@app.route("/api/auth", methods=["POST"])
def telegram_auth():
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    telegram_user = verify_telegram_init_data(init_data)

    if not telegram_user:
        return jsonify({
            "status": "error",
            "message": "Invalid or expired Telegram login"
        }), 401

    return jsonify({
        "status": "success",
        "user": {
            "id": telegram_user.get("id"),
            "first_name": telegram_user.get("first_name", ""),
            "username": telegram_user.get("username", "")
        }
    }), 200


# ADMIN SECURITY
def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        admin_key = os.getenv("ADMIN_API_KEY")
        provided_key = request.headers.get("X-Admin-Key")

        if not admin_key:
            return jsonify({"status": "error", "message": "Admin key not configured"}), 503

        if not provided_key or not secrets.compare_digest(provided_key, admin_key):
            return jsonify({"status": "error", "message": "Unauthorized"}), 401

        return func(*args, **kwargs)
    return wrapper


@app.route("/")
def home():
    return jsonify({
        "status": "success",
        "project": "REVNORA",
        "message": "REVNORA Backend is running!"
    })


# USER REGISTRATION
@app.route("/api/register", methods=["POST"])
@telegram_user_required
def register():
    data = request.get_json(silent=True) or {}
    telegram_id = data.get("telegram_id")

    if not telegram_id:
        return jsonify({"status": "error", "message": "telegram_id is required"}), 400

    try:
        telegram_id = int(telegram_id)
    except (ValueError, TypeError):
        return jsonify({"status": "error", "message": "Invalid telegram_id"}), 400

    username = data.get("username", "")
    first_name = data.get("first_name", "")
    referral_code = data.get("referral_code")

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT telegram_id, referral_code FROM users WHERE telegram_id = ?",
            (telegram_id,)
        )
        existing = cursor.fetchone()

        if existing:
            return jsonify({
                "status": "success",
                "message": "User already registered",
                "referral_code": existing["referral_code"]
            }), 200

        referred_by = None

        if referral_code:
            cursor.execute(
                "SELECT telegram_id FROM users WHERE referral_code = ?",
                (str(referral_code).strip().upper(),)
            )
            referrer = cursor.fetchone()

            if not referrer:
                return jsonify({"status": "error", "message": "Invalid referral code"}), 400

            if referrer["telegram_id"] == telegram_id:
                return jsonify({"status": "error", "message": "Self referral not allowed"}), 400

            referred_by = referrer["telegram_id"]

        new_code = secrets.token_hex(4).upper()

        cursor.execute("""
            INSERT INTO users
            (telegram_id, username, first_name, referral_code, referred_by)
            VALUES (?, ?, ?, ?, ?)
        """, (telegram_id, username, first_name, new_code, referred_by))

        conn.commit()

        return jsonify({
            "status": "success",
            "message": "User registered successfully",
            "referral_code": new_code
        }), 201

    except Exception as e:
        conn.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        conn.close()


# USER BALANCE
@app.route("/api/balance/<int:telegram_id>")
@telegram_user_required
def get_balance(telegram_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT coins FROM users WHERE telegram_id = ?", (telegram_id,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    return jsonify({
        "status": "success",
        "telegram_id": telegram_id,
        "coins": user["coins"]
    })


# USER TRANSACTIONS
@app.route("/api/transactions/<int:telegram_id>")
@telegram_user_required
def get_transactions(telegram_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT amount, transaction_type, description, created_at
        FROM transactions
        WHERE telegram_id = ?
        ORDER BY id DESC
    """, (telegram_id,))

    transactions = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify({
        "status": "success",
        "telegram_id": telegram_id,
        "transactions": transactions
    })


# ACTIVE TASKS
@app.route("/api/tasks")
def get_tasks():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, title, description, task_type, reward_coins, target_url
        FROM tasks WHERE status = 'active'
    """)

    tasks = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify({
        "status": "success",
        "total_tasks": len(tasks),
        "tasks": tasks
    })


# WITHDRAWAL REQUEST
@app.route("/api/withdraw", methods=["POST"])
@telegram_user_required
def withdraw():
    data = request.get_json(silent=True) or {}

    try:
        telegram_id = int(data.get("telegram_id"))
        amount = int(data.get("amount"))
    except (ValueError, TypeError):
        return jsonify({"status": "error", "message": "Valid details required"}), 400

    payment_method = data.get("payment_method")
    payment_details = data.get("payment_details")

    if amount <= 0 or not payment_method or not payment_details:
        return jsonify({"status": "error", "message": "Invalid withdrawal details"}), 400

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT coins FROM users WHERE telegram_id = ?", (telegram_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404

    if user["coins"] < amount:
        conn.close()
        return jsonify({"status": "error", "message": "Insufficient coin balance"}), 400

    cursor.execute("""
        INSERT INTO withdrawals
        (telegram_id, amount, payment_method, payment_details)
        VALUES (?, ?, ?, ?)
    """, (telegram_id, amount, payment_method, payment_details))

    conn.commit()
    conn.close()

    return jsonify({
        "status": "success",
        "message": "Withdrawal request submitted"
    }), 201


# REFERRAL DETAILS
@app.route("/api/referral/<int:telegram_id>")
@telegram_user_required
def get_referral(telegram_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT referral_code FROM users WHERE telegram_id = ?",
        (telegram_id,)
    )
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404

    cursor.execute(
        "SELECT COUNT(*) AS total_referrals FROM users WHERE referred_by = ?",
        (telegram_id,)
    )
    result = cursor.fetchone()
    conn.close()

    return jsonify({
        "status": "success",
        "telegram_id": telegram_id,
        "referral_code": user["referral_code"],
        "total_referrals": result["total_referrals"]
    })


# DAILY BONUS
@app.route("/api/daily/<int:telegram_id>", methods=["POST"])
@telegram_user_required
def claim_daily_bonus(telegram_id):
    reward = 10
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("BEGIN IMMEDIATE")

        cursor.execute(
            "SELECT coins FROM users WHERE telegram_id = ?",
            (telegram_id,)
        )
        user = cursor.fetchone()

        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404

        cursor.execute("""
            SELECT id FROM transactions
            WHERE telegram_id = ?
            AND transaction_type = 'daily_bonus'
            AND date(created_at, '+5 hours', '+30 minutes') =
                date('now', '+5 hours', '+30 minutes')
        """, (telegram_id,))

        if cursor.fetchone():
            return jsonify({
                "status": "error",
                "message": "Daily bonus already claimed today"
            }), 400

        cursor.execute(
            "UPDATE users SET coins = coins + ? WHERE telegram_id = ?",
            (reward, telegram_id)
        )

        cursor.execute("""
            INSERT INTO transactions
            (telegram_id, amount, transaction_type, description)
            VALUES (?, ?, ?, ?)
        """, (telegram_id, reward, "daily_bonus", "Daily bonus claimed"))

        conn.commit()

        return jsonify({
            "status": "success",
            "message": "Daily bonus claimed successfully",
            "reward": reward
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        conn.close()


# ADMIN: VIEW USERS
@app.route("/api/admin/users")
@admin_required
def admin_users():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT telegram_id, username, first_name, coins,
               referral_code, referred_by, created_at
        FROM users ORDER BY created_at DESC
    """)

    users = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify({
        "status": "success",
        "total_users": len(users),
        "users": users
    })


# ADMIN: ADD TASK
@app.route("/api/admin/tasks", methods=["POST"])
@admin_required
def admin_add_task():
    data = request.get_json(silent=True) or {}

    title = data.get("title")
    description = data.get("description", "")
    task_type = data.get("task_type")
    target_url = data.get("target_url", "")

    try:
        reward_coins = int(data.get("reward_coins"))
    except (ValueError, TypeError):
        return jsonify({"status": "error", "message": "Invalid reward"}), 400

    if not title or not task_type or reward_coins <= 0:
        return jsonify({"status": "error", "message": "Invalid task details"}), 400

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO tasks
        (title, description, task_type, reward_coins, target_url)
        VALUES (?, ?, ?, ?, ?)
    """, (title, description, task_type, reward_coins, target_url))

    conn.commit()
    task_id = cursor.lastrowid
    conn.close()

    return jsonify({
        "status": "success",
        "message": "Task created successfully",
        "task_id": task_id
    }), 201


# ADMIN: VIEW WITHDRAWALS
@app.route("/api/admin/withdrawals")
@admin_required
def admin_withdrawals():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, telegram_id, amount, payment_method,
               payment_details, status, created_at
        FROM withdrawals ORDER BY created_at DESC
    """)

    withdrawals = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify({
        "status": "success",
        "total_withdrawals": len(withdrawals),
        "withdrawals": withdrawals
    })


# ADMIN: APPROVE OR REJECT WITHDRAWAL
@app.route("/api/admin/withdrawals/<int:withdrawal_id>", methods=["POST"])
@admin_required
def admin_update_withdrawal(withdrawal_id):
    data = request.get_json(silent=True) or {}
    action = data.get("action")

    if action not in ["approve", "reject"]:
        return jsonify({"status": "error", "message": "Invalid action"}), 400

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("BEGIN IMMEDIATE")

        cursor.execute(
            "SELECT * FROM withdrawals WHERE id = ?",
            (withdrawal_id,)
        )
        withdrawal = cursor.fetchone()

        if not withdrawal:
            return jsonify({"status": "error", "message": "Withdrawal not found"}), 404

        if withdrawal["status"] != "pending":
            return jsonify({"status": "error", "message": "Already processed"}), 400

        if action == "approve":
            cursor.execute("""
                UPDATE users SET coins = coins - ?
                WHERE telegram_id = ? AND coins >= ?
            """, (
                withdrawal["amount"],
                withdrawal["telegram_id"],
                withdrawal["amount"]
            ))

            if cursor.rowcount == 0:
                return jsonify({"status": "error", "message": "Insufficient balance"}), 400

            cursor.execute("""
                INSERT INTO transactions
                (telegram_id, amount, transaction_type, description)
                VALUES (?, ?, ?, ?)
            """, (
                withdrawal["telegram_id"],
                -withdrawal["amount"],
                "withdrawal",
                "Withdrawal approved"
            ))

            new_status = "approved"
        else:
            new_status = "rejected"

        cursor.execute(
            "UPDATE withdrawals SET status = ? WHERE id = ?",
            (new_status, withdrawal_id)
        )

        conn.commit()

        return jsonify({
            "status": "success",
            "message": "Withdrawal " + new_status,
            "withdrawal_id": withdrawal_id
        })

    except Exception as e:
        conn.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        conn.close()


# ADMIN: ADD OR REMOVE USER COINS
@app.route("/api/admin/coins", methods=["POST"])
@admin_required
def admin_adjust_coins():
    data = request.get_json(silent=True) or {}

    try:
        telegram_id = int(data.get("telegram_id"))
        amount = int(data.get("amount"))
    except (ValueError, TypeError):
        return jsonify({
            "status": "error",
            "message": "Valid telegram_id and amount are required"
        }), 400

    description = str(data.get("description", "Admin coin adjustment")).strip()

    if amount == 0:
        return jsonify({
            "status": "error",
            "message": "Amount cannot be zero"
        }), 400

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("BEGIN IMMEDIATE")

        cursor.execute(
            "SELECT coins FROM users WHERE telegram_id = ?",
            (telegram_id,)
        )
        user = cursor.fetchone()

        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404

        if user["coins"] + amount < 0:
            return jsonify({
                "status": "error",
                "message": "Balance cannot become negative"
            }), 400

        cursor.execute(
            "UPDATE users SET coins = coins + ? WHERE telegram_id = ?",
            (amount, telegram_id)
        )

        transaction_type = "admin_credit" if amount > 0 else "admin_debit"

        cursor.execute("""
            INSERT INTO transactions
            (telegram_id, amount, transaction_type, description)
            VALUES (?, ?, ?, ?)
        """, (telegram_id, amount, transaction_type, description))

        cursor.execute(
            "SELECT coins FROM users WHERE telegram_id = ?",
            (telegram_id,)
        )
        updated_user = cursor.fetchone()

        conn.commit()

        return jsonify({
            "status": "success",
            "message": "User coins updated successfully",
            "telegram_id": telegram_id,
            "adjustment": amount,
            "new_balance": updated_user["coins"]
        })

    except Exception as e:
        conn.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        conn.close()


if __name__ == "__main__":
    app.run(debug=True)
