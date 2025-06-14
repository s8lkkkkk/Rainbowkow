import requests

def check_webhook(webhook_url):
    test_message = {
        "content": "✅ Webhook is working!",
        "username": "Webhook Checker"
    }

    try:
        response = requests.post(webhook_url, json=test_message)

        if response.status_code == 204:
            print("\n✅ Webhook is valid and working!")
        elif response.status_code == 404:
            print("\n❌ Webhook URL is invalid or has been deleted (404).")
        elif response.status_code in [401, 403]:
            print("\n❌ Webhook is unauthorized or access is forbidden.")
        else:
            print(f"\n⚠️ Webhook responded with status code: {response.status_code}")
            print("Response:", response.text)

    except requests.exceptions.RequestException as e:
        print(f"\n❌ Error connecting to webhook: {e}")

if __name__ == "__main__":
    print("🔗 Paste your Discord Webhook URL below and press Enter:")
    url = input("Webhook URL: ").strip()
    check_webhook(url)
