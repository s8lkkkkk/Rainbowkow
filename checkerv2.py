import secrets
import requests
import time
import hashlib
from ecdsa import SigningKey, SECP256k1
import json

# Your Discord webhook URL
WEBHOOK_URL = "https://discord.com/api/webhooks/1370714262237876224/od1EsdVEJ869kBHZB7vqGqXjOM55pcaK9NbPf_J97AUY5GFnHrVsRVcO-qB0oXY_012a"

# Console colors
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

def generate_private_key():
    return secrets.token_hex(32)

def private_key_to_address(private_key_hex):
    private_key_bytes = bytes.fromhex(private_key_hex)
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    pub_key = b'\x04' + vk.to_string()
    try:
        import sha3
        keccak_hash = sha3.keccak_256(pub_key).digest()
    except ImportError:
        keccak_hash = hashlib.sha3_256(pub_key).digest()
    address = "0x" + keccak_hash[-20:].hex()
    return address

def check_balance(address, chain, rpc_url):
    headers = {"Content-Type": "application/json"}
    data = {
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [address, "latest"],
        "id": 1
    }
    try:
        response = requests.post(rpc_url, headers=headers, data=json.dumps(data), timeout=10)
        result = response.json()
        wei = int(result.get("result", "0x0"), 16)
        return wei / 10**18
    except Exception as e:
        print(f"Error on {chain} for {address}: {e}")
        return 0

def send_to_discord(message):
    data = {"content": message}
    try:
        requests.post(WEBHOOK_URL, json=data)
    except Exception as e:
        print(f"Failed to send Discord message: {e}")

try:
    while True:
        for _ in range(10):  # Generate and check 10 keys
            priv_key = generate_private_key()
            address = private_key_to_address(priv_key)
            found = False
            balances = {}

            for chain, rpc_url in RPC_ENDPOINTS.items():
                balance = check_balance(address, chain, rpc_url)
                balances[chain] = balance

                # Color red if zero, green if >0
                if balance > 0:
                    color = GREEN
                    found = True
                else:
                    color = RED

                print(f"{chain} | Checked {address} - {color}{balance}{RESET}")

            if found:
                print(f"\n*** Balance found! ***")
                print(f"Address: {address}")
                print(f"Private Key: 0x{priv_key}\n")
                with open("keys.txt", "a") as f:
                    f.write(f"{address} : 0x{priv_key}\n")

                # Prepare Discord message
                msg = f"💰 **Balance found!**\nAddress: `{address}`\n"
                for chain, bal in balances.items():
                    status = "🟢" if bal > 0 else "🔴"
                    msg += f"{status} {chain}: {bal:.6f}\n"
                msg += f"Private Key: ||0x{priv_key}||"  # spoiler tags to hide key

                send_to_discord(msg)

            else:
                time.sleep(0.1)
        time.sleep(1)

except KeyboardInterrupt:
    print("\nStopped by user.")
