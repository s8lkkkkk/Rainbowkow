import requests

def check_cookie(cookie):
    headers = {
        "Cookie": f".ROBLOSECURITY={cookie}",
        "User-Agent": "Roblox/WinInet",
        "Accept": "application/json"
    }
    try:
        res = requests.get("https://www.roblox.com/mobileapi/userinfo", headers=headers)
        if res.status_code == 200:
            user = res.json()
            print(f"[VALID] {user['UserName']} | User ID: {user['UserID']}")
            return True
        else:
            print("[INVALID] Cookie is not valid.")
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
        print(f"[ERROR] File '{filename}' not found.")

if __name__ == "__main__":
    check_cookies_from_file("cookies.txt")
