# Zerathon: Hackers stop here.

Defense-in-depth security plugin for websites, apps, APIs, and AI apps.

## What you get
- Skill (`skills/zerathon/SKILL.md`) that audits and hardens a project
- Master prompts: runtime guardian (Prompt A) and auditor (Prompt B)
- Ready guard code: Python (Flask, FastAPI) and Node (Express), zero dependencies
- `/zerathon-audit` slash command

## Layers
Rate limiting, anomaly risk score (0-100), auto-block with escalating bans, SQLi/XSS/traversal/command-injection detection, prompt-injection shield, scanner and bot detection, honeypot traps, brute-force protection, geo-block, allow/deny lists, secrets scanner, security headers, audit log (JSONL), Telegram alerts, kill switch.

## Install
**Claude Code:** copy this folder to a plugin directory, or add it through a marketplace, then run `/zerathon-audit`.
**Claude.ai skill only:** zip the `skills/zerathon` folder and upload it in Settings, Capabilities, Skills.
**Guard only:** copy `scripts/zerathon_guard.py` or `scripts/zerathon-guard.js` into your project.

## Quick start
```python
from flask import Flask
from zerathon_guard import Zerathon, init_flask
app = Flask(__name__)
guard = Zerathon(trust_proxy=True, deny_countries=[])
init_flask(app, guard)
```
```js
const { Zerathon } = require('./zerathon-guard');
const guard = new Zerathon({ trustProxy: true });
app.use(guard.middleware());
```
Alerts: set `ZERATHON_TG_TOKEN` and `ZERATHON_TG_CHAT`.

## Limits (read this)
No tool makes an app 100% unhackable. Zerathon cuts risk and automates response. Also use HTTPS, Cloudflare, 2FA, dependency updates, and keep secrets out of code. In-memory bans reset on restart; use Redis for multi-server setups.
