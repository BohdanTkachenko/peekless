#!/usr/bin/env python3
"""Probe every relay in relays.json; drop those that fail all attempts."""
import json, time, urllib.request

ATTEMPTS, DELAY = 3, 60

def healthy(url):
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/v1/health", timeout=10) as r:
            return json.load(r).get("protocol") == "peekless/1"
    except Exception:
        return False

data = json.load(open("relays.json"))
dead = {r["url"] for r in data["relays"]}
for attempt in range(ATTEMPTS):
    dead = {u for u in dead if not healthy(u)}
    if not dead:
        break
    if attempt + 1 < ATTEMPTS:
        time.sleep(DELAY)
data["relays"] = [r for r in data["relays"] if r["url"] not in dead]
json.dump(data, open("relays.json", "w"), indent=2)
open("relays.json", "a").write("\n")
with open("relay-report.txt", "w") as f:
    f.write("Unreachable after %d probes:\n" % ATTEMPTS + "".join(f"- {u}\n" for u in sorted(dead)))
print("dead:", sorted(dead) or "none")
