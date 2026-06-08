import urllib.request
import json
import time

def start_scan():
    req = urllib.request.Request("http://localhost:5000/api/scan/start", method="POST")
    with urllib.request.urlopen(req) as res:
        print("Scan started")

def get_networks():
    req = urllib.request.Request("http://localhost:5000/api/networks")
    with urllib.request.urlopen(req) as res:
        data = json.loads(res.read().decode())
        print(f"Networks size: {len(data)}")

def stop_scan():
    req = urllib.request.Request("http://localhost:5000/api/scan/stop", method="POST")
    with urllib.request.urlopen(req) as res:
        print("Scan stopped")

print("Starting scan")
start_scan()
time.sleep(5)
print("Fetching networks (first time)")
get_networks()
print("Stopping scan")
stop_scan()
time.sleep(1)
print("Fetching networks (after stop)")
get_networks()
