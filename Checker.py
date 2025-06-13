import secrets
from web3 import Web3
import time

# Setup your Alchemy URL
alchemy_url = "https://eth-mainnet.g.alchemy.com/v2/kXg5eHzREfbkY0c7uxkdGOIRnjxHqby-"  # Replace this
web3 = Web3(Web3.HTTPProvider(alchemy_url))

if not web3.isConnected():
    print("Failed to connect to Ethereum network.")
    exit()

def generate_private_key():
    return "0x" + secrets.token_hex(32)

def private_key_to_address(private_key):
    acct = web3.eth.account.from_key(private_key)
    return acct.address

def check_balance(address):
    balance_wei = web3.eth.get_balance(address)
    return web3.fromWei(balance_wei, 'ether')

try:
    while True:
        priv_key = generate_private_key()
        addr = private_key_to_address(priv_key)
        balance = check_balance(addr)
        if balance > 0:
            print(f"\n*** Found wallet with balance! ***")
            print(f"Address: {addr}")
            print(f"Private Key: {priv_key}")
            print(f"Balance: {balance} ETH\n")
        else:
            print(f"Checked {addr} - balance is zero.")
        
        time.sleep(1)  # 1 second delay between checks

except KeyboardInterrupt:
    print("\nStopped by user.")
