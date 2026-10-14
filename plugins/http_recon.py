"""
plugins/http_recon.py
Non-invasive reconnaissance plugin: fetches a small set of benign paths and extracts links.
"""
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class Plugin:
    def __init__(self, config):
        self.enabled = config.plugins_config.get("http_recon", {}).get("enabled", True)
        self.config = config
        self.requires_explicit_authorization = False

    async def discover(self, target, runner, storage):
        results = {"time": __import__("datetime").datetime.utcnow().isoformat(), "target": target, "actions": []}
        for path in ["/", "/robots.txt", "/.well-known/security.txt", "/sitemap.xml"]:
            url = target.rstrip("/") + path
            try:
                r = await runner.http_get(url, timeout=10)
                item = {"url": url, "status": r["status"], "headers": r["headers"]}
                if path == "/" and r["status"] == 200:
                    soup = BeautifulSoup(r["body"], "html.parser")
                    links = set()
                    for a in soup.find_all("a", href=True):
                        links.add(urljoin(url, a["href"]))
                    item["links"] = list(links)[:200]
                results["actions"].append(item)
                storage.save_endpoint(url, item["status"], item.get("headers"))
            except Exception as e:
                results["actions"].append({"url": url, "error": str(e)})
        return results

    async def validate(self, candidate, runner, storage):
        # http_recon does not provide vulnerability validation
        return None
