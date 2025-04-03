import requests
import base64
import getpass
import urllib3

# Suppress SSL certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to read gateways from file
def read_gateways(file_path):
    gateways = []
    with open(file_path, 'r') as file:
        for line in file:
            name, ip = line.strip().split(', ')
            gateways.append((name, ip))
    return gateways

# Function to log in to the gateway
def login(ip, username, password):
    url = f"https://{ip}:4434/web-api/login"
    payload = {"user": username, "password": password}
    
    print(f"[INFO] Logging in to {ip}...")
    try:
        response = requests.post(url, json=payload, verify=False)  # SSL verification disabled
        if response.status_code == 200:
            print(f"[SUCCESS] Logged in to {ip}")
            return response.json().get('sid')
        else:
            print(f"[ERROR] Login failed for {ip}: {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Unable to connect to {ip}: {e}")
        return None

# Function to run clish command
def run_clish_command(ip, sid, command):
    url = f"https://{ip}:4434/web-api/run-clish-command"
    encoded_command = base64.b64encode(command.encode()).decode()
    payload = {"script": encoded_command}
    headers = {"Content-Type": "application/json", "x-chkp-sid": sid}
    
    print(f"[INFO] Running Clish command on {ip}...")
    try:
        response = requests.post(url, json=payload, headers=headers, verify=False)  # SSL verification disabled
        if response.status_code == 200:
            output = response.json().get('output')
            decoded_output = base64.b64decode(output).decode().strip()

            # Check if "bad parameter" is present (case-insensitive)
            if "bad parameter" in decoded_output.lower():
                print(f"[FAILED] Command execution failed on {ip}: Bad parameter error\n{decoded_output}")
            else:
                print(f"[SUCCESS] Command executed on {ip}:\n{decoded_output}")
        else:
            print(f"[ERROR] Command execution failed on {ip}: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Unable to send command to {ip}: {e}")

# Function to log out from the gateway
def logout(ip, sid):
    url = f"https://{ip}:4434/web-api/logout"
    headers = {"Content-Type": "application/json", "x-chkp-sid": sid}
    
    print(f"[INFO] Logging out from {ip}...")
    try:
        response = requests.post(url, headers=headers, verify=False)  # SSL verification disabled
        if response.status_code == 200:
            print(f"[SUCCESS] Logged out from {ip}")
        else:
            print(f"[ERROR] Logout failed for {ip}: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Unable to log out from {ip}: {e}")

def main():
    gateways = read_gateways('gateways.txt')
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    command = input("Enter Clish Command: ")

    for name, ip in gateways:
        print(f"\n[PROCESSING] {name} ({ip})...")
        sid = login(ip, username, password)
        if sid:
            run_clish_command(ip, sid, command)
            logout(ip, sid)
        else:
            print(f"[SKIPPED] Skipping {name} ({ip}) due to login failure.")

if __name__ == "__main__":
    main()
