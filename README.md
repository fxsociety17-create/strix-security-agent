# Autonomous Security Agent (starter)

This project is a minimal, safe-by-default autonomous security assessment agent.

Important safety notes:
- The agent will refuse network actions outside the allowlist.
- Active / invasive tests (exploitation, SSRF, RCE, sandbox escapes) are disabled by default. Enable only after you attach explicit authorization (signed statement, test-account evidence).
- Rate-limiting defaults to 5 QPS to match many bug-bounty rules.

Quickstart:
1. Create a config.json (see config.example.json).
2. Populate allowlist and explicit_authorization ONLY if you have authorization.
3. python -m venv .venv && source .venv/bin/activate
4. pip install -r requirements.txt
5. Run a test (safe recon only):
   python agent.py config.example.json https://example.com
6. Generate report:
   The agent prints a Markdown report to stdout; storage.db contains logs and artifacts.

Before enabling active plugins:
- Confirm legal authorization (signed doc, HackerOne program acceptance, or written permission from the asset owner).
- Verify scope, allowed domains, and test accounts.
- Review plugin code; invasive plugins must require `explicit_authorization` in config.

For production use:
- Add authentication for human approval before any active plugin runs.
- Add process-level resource limits and containerize the agent.
- Integrate secure secrets manager (Vault/Keyring) for model APIs; never store raw credentials in logs.
