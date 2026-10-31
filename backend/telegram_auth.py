
import os
import hmac
import json
import hashlib
import time
from urllib.parse import parse_qsl
from dotenv import load_dotenv

load_dotenv()


def verify_telegram_init_data(init_data, max_age=86400):
    bot_token = os.getenv("BOT_TOKEN")

    if not bot_token or not init_data:
        return None

    try:
        parsed_data = dict(parse_qsl(init_data, keep_blank_values=True))
        received_hash = parsed_data.pop("hash", None)

        if not received_hash:
            return None

        data_check_string = "\n".join(
            f"{key}={value}"
            for key, value in sorted(parsed_data.items())
        )

        secret_key = hmac.new(
            b"WebAppData",
            bot_token.encode(),
            hashlib.sha256
        ).digest()

        calculated_hash = hmac.new(
            secret_key,
            data_check_string.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(calculated_hash, received_hash):
            return None

        auth_date = int(parsed_data.get("auth_date", "0"))

        if auth_date > int(time.time()):
            return None

        if int(time.time()) - auth_date > max_age:
            return None

        user_data = parsed_data.get("user")

        if not user_data:
            return None

        return json.loads(user_data)

    except (ValueError, TypeError, json.JSONDecodeError):
        return None
