import os
import json
import time
import math
import threading
import concurrent.futures
from datetime import datetime
import requests

from google_auth_oauthlib.flow import InstalledAppFlow

# --- Utility Functions ---

def get_timestamp():
    now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S")

def log(message, type="INFO"):
    print(f"[{get_timestamp()}] [{type}] {message}")

# --- Configuration ---
base_dir = os.path.dirname(os.path.abspath(__file__))
config = {
    "google": {
        # Path to your client_secret.json file (saved as described above)
        "client_secrets_file": os.path.join(base_dir, "client_secret.json"),
        # Scopes required to get the id_token (openid is required)
        "scopes": ["openid", "email", "profile"]
    },
    "firebase": {
        # Your Firebase Web API key from your Firebase project settings
        "apiKey": "AIzaSyAGaegw8n_6MQAvB1CNLztXh4JYMf3bE5M"
    },
    "stork": {
        "baseURL": "https://app-api.jp.stork-oracle.network/v1",
        "authURL": "https://api.jp.stork-oracle.network/auth",
        "intervalSeconds": 10,
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "origin": "chrome-extension://knnliglhgkmlblppdejchidfihjnockl"
    },
    "threads": {
        "maxWorkers": 10,
        "proxyFile": os.path.join(base_dir, "proxies.txt")
    }
}

# --- Google OAuth Flow ---

class GoogleOAuth:
    def __init__(self, client_secrets_file, scopes):
        self.client_secrets_file = client_secrets_file
        self.scopes = scopes

    def get_google_id_token(self):
        log("Starting Google OAuth flow. A browser window will open for authentication.")
        flow = InstalledAppFlow.from_client_secrets_file(
            self.client_secrets_file,
            scopes=self.scopes
        )
        # Run a local server to complete the OAuth flow.
        creds = flow.run_local_server(port=0)
        if not hasattr(creds, "id_token") or creds.id_token is None:
            raise Exception("Failed to obtain Google ID token")
        log("Google OAuth authentication successful.")
        return creds.id_token

# --- Firebase Authentication via Google ---

class FirebaseAuthGoogle:
    def __init__(self, google_id_token, api_key):
        self.google_id_token = google_id_token
        self.api_key = api_key

    def authenticate(self):
        log("Authenticating with Firebase using Google OAuth token...")
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key={self.api_key}"
        payload = {
            "postBody": f"id_token={self.google_id_token}&providerId=google.com",
            "requestUri": "http://localhost",
            "returnIdpCredential": True,
            "returnSecureToken": True
        }
        response = requests.post(url, json=payload)
        response.raise_for_status()
        data = response.json()
        expires_in = int(data.get("expiresIn", "3600")) * 1000  # Convert seconds to milliseconds
        token_data = {
            "accessToken": data["idToken"],
            "idToken": data["idToken"],
            "refreshToken": data["refreshToken"],
            "expiresIn": expires_in
        }
        log("Firebase authentication via Google OAuth successful.")
        return token_data

# --- Token Management ---
# This class uses GoogleOAuth to obtain a Google ID token and then exchanges it with Firebase.
class TokenManager:
    def __init__(self):
        google_config = config["google"]
        self.google_auth = GoogleOAuth(google_config["client_secrets_file"], google_config["scopes"])
        self.firebase_auth = None
        self.tokens = None
        self.token_time = 0

    def get_valid_token(self):
        if self.tokens is None or self.is_token_expired():
            google_id_token = self.google_auth.get_google_id_token()
            self.firebase_auth = FirebaseAuthGoogle(google_id_token, config["firebase"]["apiKey"])
            self.tokens = self.firebase_auth.authenticate()
            self.token_time = int(time.time() * 1000)
        return self.tokens["accessToken"]

    def is_token_expired(self):
        if self.tokens is None:
            return True
        current_time = int(time.time() * 1000)
        return current_time >= (self.token_time + self.tokens["expiresIn"])

# --- Proxy Loading ---

def load_proxies():
    proxy_file = config["threads"].get("proxyFile")
    if not proxy_file or not os.path.exists(proxy_file):
        log("Proxy file not found. Creating an empty proxy file.", "WARN")
        if proxy_file:
            with open(proxy_file, "w", encoding="utf-8") as f:
                f.write("")
        return []
    try:
        with open(proxy_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        proxies = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
        log(f"Loaded {len(proxies)} proxies from {proxy_file}")
        return proxies
    except Exception as e:
        log(f"Error loading proxies: {str(e)}", "ERROR")
        return []

def get_proxy_dict(proxy):
    if not proxy:
        return None
    if proxy.startswith("http") or proxy.startswith("socks4") or proxy.startswith("socks5"):
        return {"http": proxy, "https": proxy}
    raise Exception(f"Unsupported proxy protocol: {proxy}")

# --- API Calls ---

def get_signed_prices(access_token):
    try:
        log("Fetching signed prices data...")
        url = f"{config['stork']['baseURL']}/stork_signed_prices"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Origin": config["stork"]["origin"],
            "User-Agent": config["stork"]["userAgent"]
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data_obj = response.json().get("data", {})
        result = []
        for asset_key, asset_data in data_obj.items():
            ts = datetime.utcfromtimestamp(asset_data["timestamped_signature"]["timestamp"] / 1000000).isoformat() + "Z"
            item = {
                "asset": asset_key,
                "msg_hash": asset_data["timestamped_signature"]["msg_hash"],
                "price": asset_data["price"],
                "timestamp": ts
            }
            item.update(asset_data)
            result.append(item)
        log(f"Successfully retrieved {len(result)} signed prices")
        return result
    except Exception as e:
        log(f"Error getting signed prices: {str(e)}", "ERROR")
        raise

def send_validation(access_token, msg_hash, is_valid, proxy):
    try:
        agent = get_proxy_dict(proxy)
        url = f"{config['stork']['baseURL']}/stork_signed_prices/validations"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Origin": config["stork"]["origin"],
            "User-Agent": config["stork"]["userAgent"]
        }
        data = {"msg_hash": msg_hash, "valid": is_valid}
        response = requests.post(url, headers=headers, json=data, proxies=agent)
        response.raise_for_status()
        log(f"✓ Validation successful for {msg_hash[:10]}... via {proxy or 'direct'}")
        return response.json()
    except Exception as e:
        log(f"✗ Validation failed for {msg_hash[:10]}...: {str(e)}", "ERROR")
        raise

def get_user_stats(access_token):
    try:
        log("Fetching user stats...")
        url = f"{config['stork']['baseURL']}/me"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Origin": config["stork"]["origin"],
            "User-Agent": config["stork"]["userAgent"]
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json().get("data")
    except Exception as e:
        log(f"Error getting user stats: {str(e)}", "ERROR")
        raise

# --- Data Validation ---

def validate_price(price_data):
    try:
        asset = price_data.get("asset", "unknown asset")
        log(f"Validating data for {asset}")
        if not price_data.get("msg_hash") or not price_data.get("price") or not price_data.get("timestamp"):
            log("Incomplete data, considered invalid", "WARN")
            return False
        data_time = datetime.fromisoformat(price_data["timestamp"].replace("Z", "+00:00")).timestamp() * 1000
        current_time = time.time() * 1000
        time_diff_minutes = (current_time - data_time) / (1000 * 60)
        if time_diff_minutes > 60:
            log(f"Data too old ({round(time_diff_minutes)} minutes ago)", "WARN")
            return False
        return True
    except Exception as e:
        log(f"Validation error: {str(e)}", "ERROR")
        return False

def validate_and_send(price_data, access_token, proxy):
    try:
        is_valid = validate_price(price_data)
        send_validation(access_token, price_data["msg_hash"], is_valid, proxy)
        return {"success": True, "msgHash": price_data["msg_hash"], "isValid": is_valid}
    except Exception as e:
        return {"success": False, "error": str(e), "msgHash": price_data.get("msg_hash")}

previous_stats = {"validCount": 0, "invalidCount": 0}

def run_validation_process(token_manager):
    try:
        log("--------- STARTING VALIDATION PROCESS ---------")
        access_token = token_manager.get_valid_token()
        initial_user_data = get_user_stats(access_token)
        if not initial_user_data or "stats" not in initial_user_data:
            raise Exception("Could not fetch initial user stats")
        initial_valid_count = initial_user_data["stats"].get("stork_signed_prices_valid_count", 0)
        initial_invalid_count = initial_user_data["stats"].get("stork_signed_prices_invalid_count", 0)
        global previous_stats
        if previous_stats["validCount"] == 0 and previous_stats["invalidCount"] == 0:
            previous_stats["validCount"] = initial_valid_count
            previous_stats["invalidCount"] = initial_invalid_count
        signed_prices = get_signed_prices(access_token)
        proxies = load_proxies()
        if not signed_prices or len(signed_prices) == 0:
            log("No data to validate")
            user_data = get_user_stats(access_token)
            display_stats(user_data)
            return
        max_workers = config["threads"].get("maxWorkers", 10)
        log(f"Processing {len(signed_prices)} data points with {max_workers} workers...")
        chunk_size = math.ceil(len(signed_prices) / max_workers)
        batches = [signed_prices[i:i+chunk_size] for i in range(0, len(signed_prices), chunk_size)]
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for i, batch in enumerate(batches):
                proxy = proxies[i % len(proxies)] if proxies else None
                for price_data in batch:
                    futures.append(executor.submit(validate_and_send, price_data, access_token, proxy))
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
        success_count = sum(1 for r in results if r.get("success"))
        log(f"Processed {success_count}/{len(results)} validations successfully")
        updated_user_data = get_user_stats(access_token)
        new_valid_count = updated_user_data["stats"].get("stork_signed_prices_valid_count", 0)
        new_invalid_count = updated_user_data["stats"].get("stork_signed_prices_invalid_count", 0)
        actual_valid_increase = new_valid_count - previous_stats["validCount"]
        actual_invalid_increase = new_invalid_count - previous_stats["invalidCount"]
        previous_stats["validCount"] = new_valid_count
        previous_stats["invalidCount"] = new_invalid_count
        display_stats(updated_user_data)
        log("--------- VALIDATION SUMMARY ---------")
        log(f"Total data processed: {actual_valid_increase + actual_invalid_increase}")
        log(f"Successful: {actual_valid_increase}")
        log(f"Failed: {actual_invalid_increase}")
        log("--------- COMPLETE ---------")
    except Exception as e:
        log(f"Validation process stopped: {str(e)}", "ERROR")

def display_stats(user_data):
    if not user_data or "stats" not in user_data:
        log("No valid stats data available to display", "WARN")
        return
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=============================================")
    print("   STORK MINING AUTO BOT - DON'T PAY USE FREE ")
    print("   SUPPORTING AIRDROP FOUNDER'S COMMUNITY   ")
    print("=============================================")
    print(f"Time: {get_timestamp()}")
    print("---------------------------------------------")
    print(f"User: {user_data.get('email', 'N/A')}")
    print(f"ID: {user_data.get('id', 'N/A')}")
    print(f"Referral Code: {user_data.get('referral_code', 'N/A')}")
    print("---------------------------------------------")
    stats = user_data.get("stats", {})
    print("VALIDATION STATISTICS:")
    print(f"✓ Valid Validations: {stats.get('stork_signed_prices_valid_count', 0)}")
    print(f"✗ Invalid Validations: {stats.get('stork_signed_prices_invalid_count', 0)}")
    print(f"↻ Last Validated At: {stats.get('stork_signed_prices_last_verified_at', 'Never')}")
    print(f"👥 Referral Usage Count: {stats.get('referral_usage_count', 0)}")
    print("---------------------------------------------")
    print(f"Next validation in {config['stork'].get('intervalSeconds', 10)} seconds...")
    print("=============================================")

def main():
    # Ensure the Firebase API key is set.
    if not config.get("firebase", {}).get("apiKey"):
        log("ERROR: Please set your Firebase API key in the configuration.", "ERROR")
        exit(1)
    token_manager = TokenManager()
    try:
        token_manager.get_valid_token()
        log("Initial authentication successful")
    except Exception as e:
        log(f"Application failed to start: {str(e)}", "ERROR")
        exit(1)
    def validation_loop():
        while True:
            run_validation_process(token_manager)
            time.sleep(config["stork"].get("intervalSeconds", 10))
    validation_thread = threading.Thread(target=validation_loop, daemon=True)
    validation_thread.start()
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
