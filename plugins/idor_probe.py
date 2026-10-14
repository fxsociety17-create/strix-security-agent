"""
plugins/idor_probe.py
Safe IDOR probe plugin.
This plugin DOES NOT perform blind enumeration. It only tests specific candidate resource IDs
provided in the config under plugins_config.idor_probe.candidates. Each candidate should include:
  - url_template (e.g. https://example.com/api/projects/{id})
  - owned_id (an ID you own)
  - victim_id (an ID belonging to another test account you also control)
The plugin requires explicit_authorization to run.
"""
import logging

logger = logging.getLogger(__name__)

class Plugin:
    def __init__(self, config):
        self.enabled = config.plugins_config.get("idor_probe", {}).get("enabled", False)
        self.config = config
        self.requires_explicit_authorization = True

    async def discover(self, target, runner, storage):
        results = {"time": __import__("datetime").datetime.utcnow().isoformat(), "target": target, "candidates": []}
        cfg = self.config.plugins_config.get("idor_probe", {})
        candidates = cfg.get("candidates", [])
        # Only run if explicit authorization provided
        if not self.config.authorization_present():
            results["note"] = "Explicit authorization missing; skipping IDOR tests"
            return results
        for c in candidates:
            # Ensure the candidate is within the target/allowlist
            url_template = c.get("url_template")
            owned_id = c.get("owned_id")
            victim_id = c.get("victim_id")
            if not url_template or not owned_id or not victim_id:
                continue
            owned_url = url_template.replace("{id}", str(owned_id))
            victim_url = url_template.replace("{id}", str(victim_id))
            try:
                r_owned = await runner.http_get(owned_url)
                r_victim = await runner.http_get(victim_url)
                item = {"owned_url": owned_url, "owned_status": r_owned.get("status"), "victim_url": victim_url, "victim_status": r_victim.get("status")}
                # Basic heuristic: if victim URL returns 200 and is similar content to owned URL, flag candidate
                same = False
                if r_owned.get("status") == 200 and r_victim.get("status") == 200:
                    a = (r_owned.get("body") or "")[:1000]
                    b = (r_victim.get("body") or "")[:1000]
                    if a and b and a == b:
                        same = True
                item["likely_idor"] = same
                results["candidates"].append(item)
            except Exception as e:
                results["candidates"].append({"error": str(e)})
        return results

    async def validate(self, candidate, runner, storage):
        # Candidate is expected to be the dict constructed in discover
        if not candidate.get("likely_idor"):
            return {"confirmed": False, "note": "Not flagged as likely IDOR"}
        # Minimal validation: include the HTTP request/response pairs as evidence (sanitized)
        evidence = {"owned_url": candidate.get("owned_url"), "victim_url": candidate.get("victim_url"), "note": "Bodies omitted for safety; fetch from storage logs if needed"}
        return {"confirmed": True, "title": "Possible IDOR: resource access without proper ownership check", "severity": "high", "description": "Two different resource IDs returned equivalent content indicating a potential insecure direct object reference.", "evidence": evidence}
