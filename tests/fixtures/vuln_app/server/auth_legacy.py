# Intentionally vulnerable initData check (Login Widget algorithm). Do not copy.
import hashlib
import hmac
import os
from urllib.parse import parse_qsl

BOT_TOKEN = os.environ["BOT_TOKEN"]


def check_init_data(init_data: str) -> bool:
    print("init_data received:", init_data)
    data = dict(parse_qsl(init_data))
    received_hash = data.pop("hash", "")
    check_string = "\n".join(f"{k}={v}" for k, v in sorted(data.items()))
    secret = hashlib.sha256(BOT_TOKEN.encode()).digest()
    calc_hash = hmac.new(secret, check_string.encode(), hashlib.sha256).hexdigest()
    return calc_hash == received_hash
