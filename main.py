import os
import sys
import re
import base64
import json
import random
import time
import socket
import subprocess
import threading
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import config

# ================================================================
# IDENTITY & EXTRACTION (User's Logic)
# ================================================================

def extract_server_identity(node_string):
    """
    Extracts host and port to prevent duplicates.
    Format: protocol://uuid@host:port...
    """
    # Try common regex for host:port
    match = re.search(r'@([^:/]+):(\d+)', node_string)
    if match:
        return f"{match.group(1)}:{match.group(2)}"
    
    # Fallback for SS or other formats
    match_fallback = re.search(r'://([^/]+)@', node_string) # base64 inside
    if not match:
        # Try finding something that looks like host:port at the end or middle
        match_hp = re.search(r'([a-zA-Z0-9\.-]+):(\d{2,5})', node_string)
        if match_hp:
            return match_hp.group(0)
            
    return node_string

def industrial_extractor(source_text):
    """
    Industrial-grade extractor for proxy links, including base64 recursion.
    """
    patterns = {
        'vless': r'vless://[^\s]+',
        'vmess': r'vmess://[^\s]+',
        'trojan': r'trojan://[^\s]+',
        'ss': r'ss://[^\s]+',
        'hy2': r'hy2://[^\s]+',
        'tuic': r'tuic://[^\s]+'
    }
    
    found_configs = []
    
    # 1. Direct extraction
    for proto, pattern in patterns.items():
        found_configs.extend(re.findall(pattern, source_text))
    
    # 2. Base64 blocks (nested subscriptions)
    b64_blocks = re.findall(r'[A-Za-z0-9+/]{50,}=*', source_text)
    for block in b64_blocks:
        try:
            # Add padding if needed
            missing_padding = len(block) % 4
            if missing_padding:
                block += '=' * (4 - missing_padding)
            decoded = base64.b64decode(block).decode('utf-8', errors='ignore')
            found_configs.extend(industrial_extractor(decoded))
        except:
            continue
            
    # 3. Identity-based de-duplication (Internal list)
    unique_nodes = {}
    for node in found_configs:
        # Remove trailing whitespace/newlines
        node = node.strip()
        identity = extract_server_identity(node)
        if identity not in unique_nodes:
            unique_nodes[identity] = node
            
    return list(unique_nodes.values())

# ================================================================
# XRAY CONFIG GENERATION
# ================================================================

class XrayManager:
    @staticmethod
    def is_port_free(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('127.0.0.1', port)) != 0

    @staticmethod
    def get_random_port():
        for _ in range(20):
            p = random.randint(config.XRAY_PORT_RANGE[0], config.XRAY_PORT_RANGE[1])
            if XrayManager.is_port_free(p):
                return p
        return None

    @staticmethod
    def generate_config(proxy_link, listen_port):
        # Very simplified wrapper logic. In a real scenario, this would 
        # use a library like 'v2ray-url' or custom parser for each protocol.
        # For the sake of this script, we'll assume we're generating a basic 
        # xray outbound for the given protocol.
        
        # NOTE: Handling all proxy types (VMESS/VLESS/Trojan/SS) manually 
        # is complex. We'll use a template-based approach or 
        # a specialized tool if available, but here we'll mock the logic.
        
        # Real implementation would parse the URL params.
        # This is a placeholder for the logic that wraps the link for xray.
        outbound = {
            "protocol": "vless", # Default or detect
            "settings": {},
            "streamSettings": {
                "network": "tcp",
                "security": "none"
            }
        }
        
        # Logic to detect protocol and fill settings
        if proxy_link.startswith("vmess://"):
            try:
                vmess_data = json.loads(base64.b64decode(proxy_link[8:]).decode('utf-8'))
                outbound["protocol"] = "vmess"
                outbound["settings"]["vnext"] = [{
                    "address": vmess_data["add"],
                    "port": int(vmess_data["port"]),
                    "users": [{"id": vmess_data["id"], "alterId": int(vmess_data.get("aid", 0))}]
                }]
                # ... other stream settings
            except: pass
        # ... logic for VLESS, Trojan, SS, etc.
        
        config_dict = {
            "log": {"loglevel": "none"},
            "inbounds": [{
                "port": listen_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True}
            }],
            "outbounds": [outbound]
        }
        return config_dict

# ================================================================
# CHECKER LOGIC
# ================================================================

def check_proxy(proxy_link, thread_id):
    port = XrayManager.get_random_port()
    if not port:
        return {"status": "error", "reason": "No free port"}

    print(f"[{datetime.now().strftime('%H:%M:%S')}] #{thread_id} Checking: {proxy_link[:60]}...")
    
    # 1. Start Xray (Mocking process launch for code sample)
    # cmd = ["xray", "-config", "temp_config.json"]
    # proc = subprocess.Popen(cmd)
    
    # 2. Check HTTP Marker
    target = random.choice(config.CHECK_TARGETS)
    proxies = {
        'http': f'socks5h://127.0.0.1:{port}',
        'https': f'socks5h://127.0.0.1:{port}'
    }
    
    result = {
        "raw": proxy_link,
        "working": False,
        "app_found": False,
        "ping": 0,
        "speed": 0.0,
        "timestamp": datetime.now().isoformat()
    }

    try:
        # Simulate check
        # response = requests.get(target["url"], proxies=proxies, timeout=config.CONNECT_TIMEOUT)
        # if target["marker"] in response.text: result["app_found"] = True
        # result["working"] = True
        
        # 3. Speed test via librespeed-cli through proxy
        # ls_cmd = ["librespeed-cli", "--socks5", f"127.0.0.1:{port}", "--json", "--bytes", "--no-upload"]
        # speed_json = subprocess.check_output(ls_cmd)
        
        # MOCK RESULTS for demonstration
        result["working"] = random.choice([True, False])
        if result["working"]:
            result["app_found"] = random.choice([True, False])
            result["ping"] = random.randint(50, 500)
            result["speed"] = round(random.uniform(0.1, 5.0), 2)
            
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] #{thread_id} Error: {str(e)}")

    # Cleanup xray
    # proc.terminate()
    
    if result["working"]:
        status_tag = "✅ WORKING" if result["app_found"] else "⚡ FAST"
        print(f"[{datetime.now().strftime('%H:%M:%S')}] #{thread_id} {status_tag} | ping={result['ping']}ms | speed={result['speed']}MB/s")
    else:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] #{thread_id} ❌ DEAD")
        
    return result

# ================================================================
# MAIN ORCHESTRATOR
# ================================================================

def main():
    print("=== GitHub Proxy Checker Started ===")
    
    # Check run count for temp file
    run_count = 0
    if os.path.exists(config.RUN_COUNT_PATH):
        with open(config.RUN_COUNT_PATH, 'r') as f:
            run_count = int(f.read().strip())
    
    run_count += 1
    with open(config.RUN_COUNT_PATH, 'w') as f:
        f.write(str(run_count))
        
    if run_count > 1 and os.path.exists(config.TEMP_SETUP_PATH):
        print(f"Deleting {config.TEMP_SETUP_PATH} (Second run detected)")
        os.remove(config.TEMP_SETUP_PATH)
    elif not os.path.exists(config.TEMP_SETUP_PATH):
        with open(config.TEMP_SETUP_PATH, 'w') as f:
            f.write("Temporary setup file. Will be deleted on next run.")

    # Create directories
    os.makedirs("subscriptions", exist_ok=True)

    # Fetch subscriptions
    print("Fetching subscriptions...")
    all_raw_text = ""
    for url in config.SUBSCRIPTION_URLS:
        try:
            resp = requests.get(url, timeout=10)
            all_raw_text += resp.text + "\n"
        except Exception as e:
            print(f"Failed to fetch {url}: {e}")

    # Extract proxies
    print("Extracting proxies...")
    links = industrial_extractor(all_raw_text)
    print(f"Found {len(links)} unique proxies.")

    # Save to raw.txt (copy)
    with open(config.RAW_PATH, 'w', encoding='utf-8') as f:
        f.write("\n".join(links))

    # Parallel check
    results = []
    with ThreadPoolExecutor(max_workers=config.MAX_WORKERS) as executor:
        futures = {executor.submit(check_proxy, link, i): link for i, link in enumerate(links)}
        for future in futures:
            results.append(future.result())

    # Sorting & Saving
    working_links = []
    fast_links = []
    
    for r in results:
        if r["working"]:
            comment = f" | ping={r['ping']} | speed={r['speed']} | checked={r['timestamp']}"
            link_with_meta = r["raw"] + "#" + comment
            if r["app_found"]:
                working_links.append(link_with_meta)
            else:
                fast_links.append(link_with_meta)

    # Write files
    with open(config.WORKING_PATH, 'w', encoding='utf-8') as f:
        f.write("\n".join(working_links))
    with open(config.FAST_PATH, 'w', encoding='utf-8') as f:
        f.write("\n".join(fast_links))

    print(f"Done. Working: {len(working_links)}, Fast: {len(fast_links)}")

if __name__ == "__main__":
    main()
