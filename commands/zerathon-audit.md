---
description: Run a Zerathon security audit on the current project and add the guard
argument-hint: [path or framework]
---

Use the zerathon skill to audit this project ($ARGUMENTS if given, otherwise the current directory).

1. Detect the stack and list entry points, auth, data stores, uploads, and AI/LLM calls.
2. Scan for hardcoded secrets first and mask anything found.
3. Audit against the Zerathon checklist and report findings as a table (ID | Severity | File:line | Why | Fix).
4. Ask me which fixes to apply, then make minimal diffs.
5. Install the matching Zerathon guard and security headers.
6. Finish with: protected now, NOT covered, next steps. Never claim the app is unhackable.
