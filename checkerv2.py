import secrets
import requests
import hashlib
from ecdsa import SigningKey, SECP256k1
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    keccak_hash = hashlib.new('sha3_256', pub_key).digest()
    address = "0x" + keccak_hash[-20:].hex()
    return address

def check_balance(address, private_key, chain, rpc_url):
    headers = {"Content-Type": "application/json"}
    data = {
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [address, "latest"],
        "id": 1
    }
    try:
        response = requests.post(rpc_url, headers=headers, data=json.dumps(data), timeout=8)
        result = response.json()
        wei = int(result.get("result", "0x0"), 16)
        eth_value = wei / 10**18
        if eth_value > 0:
            print(f"\n*** {chain} balance found! ***")
            print(f"Address: {address}")
            print(f"Private Key: 0x{private_key}")
            print(f"Balance: {eth_value} {chain}\n")
            with open("keys.txt", "a") as f:
                f.write(f"{chain} | {address} : 0x{private_key} : {eth_value} {chain}\n")
        else:
            print(f"{chain} | Checked {address} - 0")
    except Exception as e:
        print(f"{chain} | Error checking {address}: {e}")

def scan_wallet():
    priv_key = generate_private_key()
    address = private_key_to_address(priv_key)

    with ThreadPoolExecutor(max_workers=len(RPC_ENDPOINTS)) as executor:
        futures = []
        for chain, rpc in RPC_ENDPOINTS.items():
            futures.append(executor.submit(check_balance, address, priv_key, chain, rpc))
        for _ in as_completed(futures):
            pass  # just wait for all threads to finish

# Main loop
try:
    print("Starting wallet scan (fast mode)...")
    while True:
        with ThreadPoolExecutor(max_workers=10) as executor:  # 10 parallel wallet scans
            executor.map(lambda _: scan_wallet(), range(10))
except KeyboardInterrupt:
    print("\nStopped by user.")
