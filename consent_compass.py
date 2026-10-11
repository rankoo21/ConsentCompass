# v0.2.16
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""ConsentCompass: consensus classification of a proposed data use against live privacy rules."""
from genlayer import *
from urllib.parse import urlparse
import hashlib, json

def ident(v):
    v = v.strip().upper()
    if not 3 <= len(v) <= 64 or not all(c.isalnum() or c in "-_" for c in v): raise gl.vm.UserError("invalid request id")
    return v

def https(v):
    v = v.strip(); p = urlparse(v)
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.fragment: raise gl.vm.UserError("clean HTTPS URL required")
    return v

def parse_decision(raw):
    x = json.loads(raw)
    if type(x) is not dict or set(x) != {"status", "basis", "conditions", "confidence"}: raise ValueError("bad decision")
    if x["status"] not in ("ALLOWED", "RESTRICTED", "BLOCKED", "UNCLEAR"): raise ValueError("bad status")
    c = int(x["confidence"])
    if not 0 <= c <= 100: raise ValueError("bad confidence")
    if type(x["conditions"]) is not list or len(x["conditions"]) > 10: raise ValueError("bad conditions")
    return {"status": x["status"], "basis": str(x["basis"])[:700], "conditions": [str(v)[:180] for v in x["conditions"]], "confidence": c}

class ConsentCompass(gl.Contract):
    requests: TreeMap[str, str]
    def __init__(self): pass
    def _key(self, owner, rid): return str(owner).lower() + ":" + ident(rid)

    @gl.public.write
    def create_request(self, request_id: str, policy_url: str, notice_url: str, regulator_url: str, purpose: str, data_categories: str) -> None:
        owner = str(gl.message.sender_address).lower(); rid = ident(request_id); key = self._key(owner, rid)
        if self.requests.get(key, ""): raise gl.vm.UserError("request already exists")
        urls = [https(policy_url), https(notice_url), https(regulator_url)]
        if len({urlparse(v).hostname for v in urls}) != 3: raise gl.vm.UserError("sources need three distinct hosts")
        purpose, data_categories = purpose.strip(), data_categories.strip()
        if not 15 <= len(purpose) <= 1000 or not 3 <= len(data_categories) <= 600: raise gl.vm.UserError("invalid request details")
        self.requests[key] = json.dumps({"request_id": rid, "owner": owner, "policy": urls[0], "notice": urls[1], "regulator": urls[2], "purpose": purpose, "categories": data_categories, "state": "PENDING", "status": "", "basis": "", "conditions": [], "confidence": 0, "digests": []}, sort_keys=True, separators=(",", ":"))

    @gl.public.write
    def evaluate(self, request_id: str) -> None:
        key = self._key(gl.message.sender_address, request_id); record = json.loads(self.requests.get(key, "{}"))
        if not record or record["state"] != "PENDING": raise gl.vm.UserError("request is not pending")
        captured = {}
        def run():
            bodies = [gl.nondet.web.get(u).body.decode("utf-8") for u in (record["policy"], record["notice"], record["regulator"])]
            if any(not 2 <= len(v) <= 100000 for v in bodies): raise gl.vm.UserError("policy evidence unavailable")
            captured["bodies"] = bodies
            prompt = ("Classify whether a proposed data use is permitted by the supplied privacy policy, notice, and regulator guidance. "
                      "Return JSON only: status ALLOWED, RESTRICTED, BLOCKED, or UNCLEAR; basis; conditions list; confidence 0-100. "
                      "Never invent a legal rule and choose UNCLEAR when sources conflict.\nPURPOSE:\n" + record["purpose"] +
                      "\nDATA CATEGORIES:\n" + record["categories"] + "\nPOLICY:\n" + bodies[0] + "\nNOTICE:\n" + bodies[1] + "\nREGULATOR:\n" + bodies[2])
            return parse_decision(gl.nondet.exec_prompt(prompt).strip())
        def validate(leader_result):
            if not isinstance(leader_result, gl.vm.Return): return False
            own = run(); leader = leader_result.calldata
            return leader["status"] == own["status"] and abs(int(leader["confidence"]) - int(own["confidence"])) <= 20
        result = gl.vm.run_nondet_unsafe(run, validate)
        bodies = captured["bodies"]
        record.update({"status": result["status"], "basis": result["basis"], "conditions": result["conditions"], "confidence": result["confidence"], "digests": [hashlib.sha256(v.encode()).hexdigest() for v in bodies], "state": "FINAL"})
        self.requests[key] = json.dumps(record, sort_keys=True, separators=(",", ":"))

    @gl.public.view
    def get_request(self, owner: str, request_id: str) -> str: return self.requests.get(self._key(owner, request_id), "{}")



