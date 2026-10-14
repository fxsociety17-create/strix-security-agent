"""
config.py
Configuration and allowlist enforcement. Requires explicit_authorization for invasive plugins by default.
"""
import json

class Config:
    def __init__(self, data):
        self.data = data
        self.allowlist = data.get("allowlist", [])
        self.max_qps = data.get("max_qps", 5)
        self.default_timeout_seconds = data.get("default_timeout_seconds", 15)
        self.db_path = data.get("db_path", "agent.db")
        self.enabled_plugins = data.get("enabled_plugins", ["http_recon"])
        self.plugins_config = data.get("plugins_config", {})
        # safety defaults
        self.requires_explicit_authorization = data.get("requires_explicit_authorization", True)
        self.explicit_authorization = data.get("explicit_authorization")

    @classmethod
    def from_file(cls, path):
        with open(path, "r") as f:
            data = json.load(f)
        return cls(data)

    def is_allowed(self, target: str) -> bool:
        for a in self.allowlist:
            if a in target:
                return True
        return False

    def authorization_present(self) -> bool:
        return bool(self.explicit_authorization)

    def authorization_artifact(self):
        return self.explicit_authorization
