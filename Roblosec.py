import requests

def check_cookie(cookie):
    headers = {
        "Cookie": f".ROBLOSECURITY={cookie}",
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json"
    }

    try:
        response = requests.get("https://auth.roblox.com/v1/account/info", headers=headers)
        if response.status_code == 200:
            user = response.json()
            print(f"[VALID] Username: {user['username']} | User ID: {user['id']}")
            print(f"Cookie: {cookie}\n")
            return True
        else:
            print(f"[INVALID] Cookie is not valid. Status code: {response.status_code}\n")
            return False
    except Exception as e:
        print(f"[ERROR] {str(e)}\n")
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
