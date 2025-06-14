import os
import secrets
import requests
import time
import hashlib
import json
from ecdsa import SigningKey, SECP256k1
from concurrent.futures import ThreadPoolExecutor

# Show red banner at top
def print_banner():
    os.system("clear" if os.name == "posix" else "cls")
    print("\033[91m" + r"""
███╗░░░███╗░██████╗██╗░░██╗██╗░░░░░██╗░░░██╗
████╗░████║██╔════╝╚██╗██╔╝██║░░░░░██║░░░██║
██╔████╔██║╚█████╗░░╚███╔╝░██║░░░░░╚██╗░██╔╝
██║╚██╔╝██║░╚═══██╗░██╔██╗░██║░░░░░░╚████╔╝░
██║░╚═╝░██║██████╔╝██╔╝╚██╗███████╗░░╚██╔╝░░
╚═╝░░░░░╚═╝╚═════╝░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░
""" + "\033[0m")

# Your webhook
WEBHOOK_URL = "https://discord.com/api/webhooks/1383251852216500226/TgfKmto2KmchzV5vu-Q8OKTm-Mn4MKVpmmzWXy2q-c0Qrd26ARDhaDf2d7nvJnOvwNuO"

# Terminal colors
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

# RPC endpoints for each chain
RPC_ENDPOINTS = {
    "ETH": "https://eth-mainnet.g.alchemy.com/v2/jKnVzmhmloXGRz_ag2lSW",
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
    return "0x" + keccak_hash[-20:].hex()

def check_balance(address, chain_rpc):
    chain, rpc_url = chain_rpc
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
        return chain, wei / 10**18
    except Exception as e:
        print(f"Error on {chain} for {address}: {e}")
        return chain, 0

def send_to_discord(message):
    try:
        requests.post(WEBHOOK_URL, json={"content": message})
    except Exception as e:
        print(f"Failed to send Discord message: {e}")

try:
    while True:
        print_banner()

        for _ in range(10):  # 10 wallets per cycle
            priv_key = generate_private_key()
            address = private_key_to_address(priv_key)
            found = False

            with ThreadPoolExecutor(max_workers=len(RPC_ENDPOINTS)) as executor:
                futures = [executor.submit(check_balance, address, item) for item in RPC_ENDPOINTS.items()]
                results = {}
                for f in futures:
                    chain, balance = f.result()
                    results[chain] = balance

            for chain, balance in results.items():
                color = GREEN if balance > 0 else RED
                if balance > 0:
                    found = True
                print(f"{chain} | Checked {address} - {color}{balance:.6f}{RESET}")

            if found:
                print(f"\n*** Balance found! ***")
                print(f"Address: {address}")
                print(f"Private Key: 0x{priv_key}\n")

                with open("keys.txt", "a") as f:
                    f.write(f"{address} : 0x{priv_key}\n")

                msg = f"💰 **Balance found!**\nAddress: `{address}`\n"
                for chain, bal in results.items():
                    status = "🟢" if bal > 0 else "🔴"
                    msg += f"{status} {chain}: {bal:.6f}\n"
                msg += f"Private Key: ||0x{priv_key}||"

                send_to_discord(msg)

        time.sleep(1)  # Delay between cycles

except KeyboardInterrupt:
    print("\nStopped by user.")
