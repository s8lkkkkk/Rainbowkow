import secrets
import requests
import time
import hashlib
from ecdsa import SigningKey, SECP256k1
import json

ALCHEMY_API_KEY = "kXg5eHzREfbkY0c7uxkdGOIRnjxHqby-"
ALCHEMY_URL = f"https://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_API_KEY}"

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

def check_balance(address):
    headers = {"Content-Type": "application/json"}
    data = {
        "jsonrpc":"2.0",
        "method":"eth_getBalance",
        "params":[address, "latest"],
        "id":1
    }
    response = requests.post(ALCHEMY_URL, headers=headers, data=json.dumps(data))
    if response.status_code == 200:
        result = response.json()
        wei = int(result.get("result", "0x0"), 16)
        return wei / (10 ** 18)
    return 0

try:
    while True:
        for _ in range(10):  # check 10 keys per loop
            priv_key = generate_private_key()
            address = private_key_to_address(priv_key)
            balance =
