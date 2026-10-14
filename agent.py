"""
agent.py
Autonomous agent core: plans and runs safe plugins autonomously within scope and authorization.
"""
import asyncio
import logging
from datetime import datetime
from runner import CommandRunner
from storage import Storage
from plugins import load_plugins
from config import Config

logger = logging.getLogger("agent")
logging.basicConfig(level=logging.INFO)

class AutonomousAgent:
    def __init__(self, config_path: str):
        self.config = Config.from_file(config_path)
        self.runner = CommandRunner(self.config)
        self.storage = Storage(self.config.db_path)
        self.plugins = load_plugins(self.config)
        self.stop_requested = False

    async def verify_scope(self, target: str) -> bool:
        # enforce allowlist for every network action
        if not self.config.is_allowed(target):
            logger.warning("Target not in allowlist: %s", target)
            return False
        # require explicit authorization for invasive tests
        return True

    async def plan(self, target: str):
        # Build an adaptive plan based on available plugins and evidence
        plan = []
        # Always run safe recon first
        if "http_recon" in self.plugins:
            plan.append(("plugin:http_recon:discover", {"target": target}))

        # Load other plugins but only schedule them if config allows and authorization present
        for name, plugin in self.plugins.items():
            if name == "http_recon":
                continue
            # if plugin requires explicit auth, skip unless provided
            if getattr(plugin, "requires_explicit_authorization", False) and not self.config.authorization_present():
                logger.info("Skipping invasive plugin %s because explicit authorization is missing", name)
                continue
            if plugin.enabled:
                plan.append((f"plugin:{name}:discover", {"target": target}))
        return plan

    async def run_task(self, task_name: str, params: dict):
        if self.stop_requested:
            return
        logger.info("Running task %s", task_name)
        if task_name.startswith("plugin:"):
            _, name, step = task_name.split(":", 2)
            pl = self.plugins.get(name)
            if not pl:
                logger.warning("Plugin not found: %s", name)
                return
            try:
                if step == "discover":
                    results = await pl.discover(params["target"], self.runner, self.storage)
                    self.storage.save_logs(name + ":discover", results)
                    # basic autonomous decision: if plugin returns candidates and plugin supports validate, validate
                    if hasattr(pl, "validate") and results.get("candidates"):
                        for c in results.get("candidates", [])[:10]:
                            v = await pl.validate(c, self.runner, self.storage)
                            if v and v.get("confirmed"):
                                self.storage.add_finding(self.storage.last_run_id(), v.get("title"), v.get("severity"), v.get("description"), v.get("evidence"), confirmed=True)
                            else:
                                self.storage.save_logs(name + ":validation", v or {"note":"no validation result"})
            except Exception as e:
                logger.exception("Plugin %s failed: %s", name, e)

    async def run(self, target: str):
        if not await self.verify_scope(target):
            raise RuntimeError("Target verification failed")
        plan = await self.plan(target)
        run_id = self.storage.record_run(target, plan)
        self.storage.set_last_run_id(run_id)
        for task_name, params in plan:
            if self.stop_requested:
                break
            await self.run_task(task_name, params)
        logger.info("Run complete for %s", target)
        report = self.storage.export_report_by_run(run_id)
        return report

    def stop(self):
        self.stop_requested = True

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python agent.py <config.json> <target_url>")
        sys.exit(1)
    cfg = sys.argv[1]
    target = sys.argv[2]
    a = AutonomousAgent(cfg)
    out = asyncio.run(a.run(target))
    from report import generate_markdown
    md = generate_markdown(out)
    print(md)
