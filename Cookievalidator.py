import requests

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
            print(f"[VALID] Username: {user['username']} | User ID: {user['id']}")
            print(f"Cookie: {cookie}\n")
            return True
        else:
            print(f"[INVALID] Cookie is not valid. Status code: {res.status_code}\n")
            return False
    except Exception as e:
        print(f"[ERROR] {e}\n")
        return False

def check_cookies_from_file(filename):
    try:
        with open(filename, "r") as f, open("valid.txt", "a") as valid_file:
            cookies = f.read().splitlines()
            for cookie in cookies:
                cookie = cookie.strip()
                if check_cookie(cookie):
                    valid_file.write(cookie + "\n")
    except FileNotFoundError:
        print(f"[ERROR] File '{filename}' not found.")

if __name__ == "__main__":
    check_cookies_from_file("cookies.txt")
