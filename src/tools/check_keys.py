# Copyright 2026 Abdullah Al Smadi
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# check_keys.py — Live-tests every API key in ~/.auto-cti/.env against its
# provider and reports OK/FAIL without ever printing the key itself.
import os, sys, requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.secure_config import load_env, REQUIRED_KEYS, OPTIONAL_KEYS

env = load_env()

def check(name, fn):
    val = env.get(name)
    if not val:
        print(f"{name:<24} MISSING")
        return
    try:
        ok, msg = fn(val)
        print(f"{name:<24} {'OK' if ok else 'FAIL'} {msg}")
    except Exception as e:
        print(f"{name:<24} ERROR {e}")

def gemini(v):
    r = requests.get("https://generativelanguage.googleapis.com/v1beta/models",
                     params={"key": v}, timeout=10)
    return r.status_code == 200, f"({r.status_code})"

def nvd(v):
    r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                     params={"resultsPerPage": 1},
                     headers={"apiKey": v}, timeout=15)
    return r.status_code == 200, f"({r.status_code})"

def github(v):
    r = requests.get("https://api.github.com/user",
                     headers={"Authorization": f"Bearer {v}"}, timeout=10)
    return r.status_code == 200, f"({r.status_code})"

def otx(v):
    r = requests.get("https://otx.alienvault.com/api/v1/user/me",
                     headers={"X-OTX-API-KEY": v}, timeout=10)
    return r.status_code == 200, f"({r.status_code})"

print("Required:")
check("GEMINI_API_KEY", gemini)

print("\nOptional:")
for k in OPTIONAL_KEYS:
    if k == "NVD_API_KEY":
        check(k, nvd)
    elif k == "GITHUB_TOKEN":
        check(k, github)
    elif k == "OTX_API_KEY":
        check(k, otx)
    else:
        print(f"{k:<24} {'SET' if env.get(k) else 'MISSING'}")

print("\nToggles:")
for k in ["SCOUT_SKIP_NVD", "ENABLE_SPLOITUS", "ENABLE_VULNERS_LUCENE", "ENABLE_SEEBUG"]:
    print(f"{k:<24} {env.get(k, 'false')}")