import time
import requests # pip install requests

# config
DOMAIN = "myfirstvpnnust"          # Your DuckDNS subdomain (ours is myfirstvpnnust.duckdns.org)
TOKEN = "36226024-e3ba-4eba-8a57-3931d61387b8"  # Your DuckDNS token (ours is 36226024-e3ba-4eba-8a57-3931d61387b8)
UPDATE_INTERVAL = 300      # Time in seconds 

# DuckDNS update URL
UPDATE_URL = f"https://www.duckdns.org/update?domains={DOMAIN}&token={TOKEN}&ip="


# updates ip
def update_ip():
    try:
        response = requests.get(UPDATE_URL, timeout=10)
        if response.text.strip() == "OK":
            print(f"[+] DuckDNS updated successfully for {DOMAIN}")
        else:
            print(f"[!] DuckDNS update failed: {response.text}")
    except Exception as e:
        print(f"[!] Error updating DuckDNS: {e}")

# loop
if __name__ == "__main__":
    print(f"Starting DuckDNS updater for {DOMAIN}")
    while True:
        update_ip()
        time.sleep(UPDATE_INTERVAL)
