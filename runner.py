"""
runner.py
Safe HTTP and command runner with rate limiting and timeouts.
"""
import asyncio
import shlex
import os
import logging
import aiohttp
from asyncio.subprocess import PIPE
from config import Config
from aiolimiter import AsyncLimiter

logger = logging.getLogger("runner")

class CommandRunner:
    def __init__(self, config: Config):
        self.config = config
        self.http_sem = AsyncLimiter(config.max_qps, time_period=1.0)
        self.default_timeout = config.default_timeout_seconds

    async def run_cmd(self, command: str, timeout: int = None):
        timeout = timeout or self.default_timeout
        env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_key")}
        args = shlex.split(command)
        proc = await asyncio.create_subprocess_exec(*args, stdout=PIPE, stderr=PIPE, env=env)
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode
        except asyncio.TimeoutError:
            proc.kill()
            return "", "TIMEOUT", -1

    async def http_get(self, url: str, headers: dict = None, timeout: int = None):
        timeout = aiohttp.ClientTimeout(total=timeout or self.default_timeout)
        async with self.http_sem:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers or {}, allow_redirects=True) as resp:
                    text = await resp.text(errors="replace")
                    return {"status": resp.status, "headers": dict(resp.headers), "body": text}

    async def http_request(self, method: str, url: str, **kwargs):
        timeout = aiohttp.ClientTimeout(total=kwargs.pop("timeout", self.default_timeout))
        async with self.http_sem:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.request(method, url, **kwargs) as resp:
                    try:
                        body = await resp.text(errors="replace")
                    except Exception:
                        body = ""
                    return {"status": resp.status, "headers": dict(resp.headers), "body": body}
