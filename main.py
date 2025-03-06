import os
import json
import time
import math
import threading
import concurrent.futures
from datetime import datetime
import requests
import boto3

# --- Utility Functions ---

def get_timestamp():
    now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S")

def get_formatted_date():
    return get_timestamp()

def log(message, type="INFO"):
    print(f"[{get_formatted_date()}] [{type}] {message}")

# --- Configuration Loading ---

def load_config():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, "config.json")
    default_config = {
        "cognito": {
            "region": "ap-northeast-1",
            "clientId": "5msns4n49hmg3dftp2tp1t2iuh",
            "userPoolId": "ap-northeast-1_M22I44OpC",
            "username": "",  # To be filled by user
            "password": ""   # To be filled by user
        },
        "stork": {
            "intervalSeconds": 10,
        },
        "threads": {
            "maxWorkers": 10
        }
    }
    if not os.path.exists(config_path):
        log(f"Config file not found at {config_path}, using default configuration", "WARN")
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(default_config, f, indent=2)
        return default_config
    else:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = json.load(f)
            log("Configuration loaded successfully from config.json")
            return user_config
        except Exception as e:
            log(f"Error loading config: {str(e)}", "ERROR")
            raise Exception("Failed to load configuration")

user_config = load_config()
base_dir = os.path.dirname(os.path.abspath(__file__))
config = {
    "cognito": {
        "region": user_config.get("cognito", {}).get("region", "ap-northeast-1"),
        "clientId": user_config.get("cognito", {}).get("clientId", "5msns4n49hmg3dftp2tp1t2iuh"),
        "userPoolId": user_config.get("cognito", {}).get("userPoolId", "ap-northeast-1_M22I44OpC"),
        "username": user_config.get("cognito", {}).get("username", ""),
        "password": user_config.get("cognito", {}).get("password", "")
    },
    "stork": {
        "baseURL": "https://app-api.jp.stork-oracle.network/v1",
        "authURL": "https://api.jp.stork-oracle.network/auth",
        "tokenPath": os.path.join(base_dir, "tokens.json"),
        "intervalSeconds": user_config.get("stork", {}).get("intervalSeconds", 10),
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "origin": "chrome-extension://knnliglhgkmlblppdejchidfihjnockl"
    },
    "threads": {
        "maxWorkers": user_config.get("threads", {}).get("maxWorkers", 10),
        "proxyFile": os.path.join(base_dir, "proxies.txt")
    }
}

def validate_config():
    if not config["cognito"]["username"] or not config["cognito"]["password"]:
        log("ERROR: Username and password must be set in config.json", "ERROR")
        print("\nPlease update your config.json file with your credentials:")
        print(json.dumps({
            "cognito": {
                "username": "YOUR_EMAIL",
                "password": "YOUR_PASSWORD"
            }
        }, indent=2))
        return False
    return True

# --- Proxy Loading ---

def load_proxies():
    proxy_file = config["threads"]["proxyFile"]
    if not os.path.exists(proxy_file):
        log(f"Proxy file not found at {proxy_file}, creating empty file", "WARN")
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
    # For both HTTP and SOCKS proxies (requires requests[socks] if using socks)
    if proxy.startswith("http") or proxy.startswith("socks4") or proxy.startswith("socks5"):
        return {"http": proxy, "https": proxy}
    raise Exception(f"Unsupported proxy protocol: {proxy}")

# --- AWS Cognito Authentication ---

class CognitoAuth:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.client = boto3.client('cognito-idp', region_name=config["cognito"]["region"])
        self.client_id = config["cognito"]["clientId"]

    def authenticate(self):
        try:
            response = self.client.initiate_auth(
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={
                    "USERNAME": self.username,
                    "PASSWORD": self.password
                },
                ClientId=self.client_id
            )
            auth_result = response.get("AuthenticationResult")
            if not auth_result:
                raise Exception("Authentication failed, no AuthenticationResult returned")
            # ExpiresIn is in seconds; we convert to milliseconds and calculate remaining time
            expires_in_ms = auth_result["ExpiresIn"] * 1000
            token_data = {
                "accessToken": auth_result["AccessToken"],
                "idToken": auth_result["IdToken"],
                "refreshToken": auth_result["RefreshToken"],
                "expiresIn": expires_in_ms - int(time.time() * 1000)
            }
            return token_data
        except Exception as e:
            raise Exception("Authentication error: " + str(e))

    def refresh_session(self, refresh_token):
        try:
            response = self.client.initiate_auth(
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters={
                    "REFRESH_TOKEN": refresh_token
                },
                ClientId=self.client_id
            )
            auth_result = response.get("AuthenticationResult")
            if not auth_result:
                raise Exception("Refresh session failed, no AuthenticationResult returned")
            expires_in_ms = auth_result["ExpiresIn"] * 1000
            token_data = {
                "accessToken": auth_result["AccessToken"],
                "idToken": auth_result["IdToken"],
                "refreshToken": refresh_token,
                "expiresIn": expires_in_ms - int(time.time() * 1000)
            }
            return token_data
        except Exception as e:
            raise Exception("Refresh session error: " + str(e))

# --- Token Management ---

class TokenManager:
    def __init__(self):
        self.access_token = None
        self.refresh_token = None
        self.id_token = None
        self.expires_at = 0
        self.auth = CognitoAuth(config["cognito"]["username"], config["cognito"]["password"])

    def get_valid_token(self):
        if not self.access_token or self.is_token_expired():
            self.refresh_or_authenticate()
        return self.access_token

    def is_token_expired(self):
        return int(time.time() * 1000) >= self.expires_at

    def refresh_or_authenticate(self):
        try:
            if self.refresh_token:
                result = self.auth.refresh_session(self.refresh_token)
            else:
                result = self.auth.authenticate()
            self.update_tokens(result)
        except Exception as e:
            log(f"Token refresh/auth error: {str(e)}", "ERROR")
            raise

    def update_tokens(self, result):
        self.access_token = result["accessToken"]
        self.id_token = result["idToken"]
        self.refresh_token = result["refreshToken"]
        self.expires_at = int(time.time() * 1000) + result["expiresIn"]
        tokens = {
            "accessToken": self.access_token,
            "idToken": self.id_token,
            "refreshToken": self.refresh_token,
            "isAuthenticated": True,
            "isVerifying": False
        }
        save_tokens(tokens)
        log("Tokens updated and saved to tokens.json")

def get_tokens():
    token_path = config["stork"]["tokenPath"]
    if not os.path.exists(token_path):
        raise Exception(f"Tokens file not found at {token_path}")
    try:
        with open(token_path, "r", encoding="utf-8") as f:
            tokens = json.load(f)
        if not tokens.get("accessToken") or len(tokens.get("accessToken")) < 20:
            raise Exception("Invalid access token")
        log(f"Successfully read access token: {tokens['accessToken'][:10]}...")
        return tokens
    except Exception as e:
        log(f"Error reading tokens: {str(e)}", "ERROR")
        raise

def save_tokens(tokens):
    token_path = config["stork"]["tokenPath"]
    try:
        with open(token_path, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=2)
        log("Tokens saved successfully")
        return True
    except Exception as e:
        log(f"Error saving tokens: {str(e)}", "ERROR")
        return False

def refresh_tokens(refresh_token):
    try:
        log("Refreshing access token via Stork API...")
        url = f"{config['stork']['authURL']}/refresh"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": config["stork"]["userAgent"],
            "Origin": config["stork"]["origin"]
        }
        data = {"refresh_token": refresh_token}
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        resp_json = response.json()
        tokens = {
            "accessToken": resp_json.get("access_token"),
            "idToken": resp_json.get("id_token", ""),
            "refreshToken": resp_json.get("refresh_token", refresh_token),
            "isAuthenticated": True,
            "isVerifying": False
        }
        save_tokens(tokens)
        log("Token refreshed successfully via Stork API")
        return tokens
    except Exception as e:
        log(f"Token refresh failed: {str(e)}", "ERROR")
        raise

# --- API Calls ---

def get_signed_prices(tokens):
    try:
        log("Fetching signed prices data...")
        url = f"{config['stork']['baseURL']}/stork_signed_prices"
        headers = {
            "Authorization": f"Bearer {tokens['accessToken']}",
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

def send_validation(tokens, msg_hash, is_valid, proxy):
    try:
        agent = get_proxy_dict(proxy)
        url = f"{config['stork']['baseURL']}/stork_signed_prices/validations"
        headers = {
            "Authorization": f"Bearer {tokens['accessToken']}",
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

def get_user_stats(tokens):
    try:
        log("Fetching user stats...")
        url = f"{config['stork']['baseURL']}/me"
        headers = {
            "Authorization": f"Bearer {tokens['accessToken']}",
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
        # Convert ISO timestamp to milliseconds
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

# --- Worker Function ---

def validate_and_send(price_data, tokens, proxy):
    try:
        is_valid = validate_price(price_data)
        send_validation(tokens, price_data["msg_hash"], is_valid, proxy)
        return {"success": True, "msgHash": price_data["msg_hash"], "isValid": is_valid}
    except Exception as e:
        return {"success": False, "error": str(e), "msgHash": price_data.get("msg_hash")}

# --- Main Validation Process ---

previous_stats = {"validCount": 0, "invalidCount": 0}

def run_validation_process(token_manager):
    try:
        log("--------- STARTING VALIDATION PROCESS ---------")
        tokens = get_tokens()
        initial_user_data = get_user_stats(tokens)
        if not initial_user_data or "stats" not in initial_user_data:
            raise Exception("Could not fetch initial user stats")
        initial_valid_count = initial_user_data["stats"].get("stork_signed_prices_valid_count", 0)
        initial_invalid_count = initial_user_data["stats"].get("stork_signed_prices_invalid_count", 0)

        global previous_stats
        if previous_stats["validCount"] == 0 and previous_stats["invalidCount"] == 0:
            previous_stats["validCount"] = initial_valid_count
            previous_stats["invalidCount"] = initial_invalid_count

        signed_prices = get_signed_prices(tokens)
        proxies = load_proxies()

        if not signed_prices or len(signed_prices) == 0:
            log("No data to validate")
            user_data = get_user_stats(tokens)
            display_stats(user_data)
            return

        max_workers = config["threads"]["maxWorkers"]
        log(f"Processing {len(signed_prices)} data points with {max_workers} workers...")

        chunk_size = math.ceil(len(signed_prices) / max_workers)
        batches = [signed_prices[i:i+chunk_size] for i in range(0, len(signed_prices), chunk_size)]
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for i, batch in enumerate(batches):
                proxy = proxies[i % len(proxies)] if proxies else None
                for price_data in batch:
                    futures.append(executor.submit(validate_and_send, price_data, tokens, proxy))
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        success_count = sum(1 for r in results if r.get("success"))
        log(f"Processed {success_count}/{len(results)} validations successfully")

        updated_user_data = get_user_stats(tokens)
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
    print(f"Next validation in {config['stork']['intervalSeconds']} seconds...")
    print("=============================================")

# --- Main Application Loop ---

def main():
    if not validate_config():
        exit(1)
    token_manager = TokenManager()
    try:
        token_manager.get_valid_token()
        log("Initial authentication successful")
    except Exception as e:
        log(f"Application failed to start: {str(e)}", "ERROR")
        exit(1)

    # Start the periodic validation process in a background thread
    def validation_loop():
        while True:
            run_validation_process(token_manager)
            time.sleep(config["stork"]["intervalSeconds"])
    validation_thread = threading.Thread(target=validation_loop, daemon=True)
    validation_thread.start()

    # Token refresh every 50 minutes
    def token_refresh_loop():
        while True:
            time.sleep(50 * 60)
            try:
                token_manager.get_valid_token()
                log("Token refreshed via Cognito")
            except Exception as e:
                log(f"Token refresh error: {str(e)}", "ERROR")
    refresh_thread = threading.Thread(target=token_refresh_loop, daemon=True)
    refresh_thread.start()

    # Keep the main thread alive.
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
