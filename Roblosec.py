pkg update -y && pkg install python -y && pip install requests && echo 'import requests

def check_cookie(cookie):
    headers = {
        "Cookie": f".ROBLOSECURITY={cookie}",
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json"
    }
    try:
        res = requests.get("https://auth.roblox.com/v1/account/info", headers=headers)
        if res.status_code == 200:
            user = res.json()
            print(f"[VALID] {user['username']} | User ID: {user['id']}")
            return True
        else:
            print(f"[INVALID] Cookie is not valid. Status code: {res.status_code}")
            return False
    except Exception as e:
        print(f"[ERROR] {str(e)}")
        return False

def check_cookies_from_file(filename):
    try:
        with open(filename, "r") as f:
            cookies = f.read().splitlines()
            for cookie in cookies:
                check_cookie(cookie.strip())
    except FileNotFoundError:
        print(f"[ERROR] File \'{filename}\' not found.")

if __name__ == "__main__":
    check_cookies_from_file("cookies.txt")' > check_roblox_cookies.py
