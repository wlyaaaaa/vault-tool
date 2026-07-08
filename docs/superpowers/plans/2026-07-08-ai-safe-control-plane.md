# AI-safe Control Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `assess --json` and `plan --json` commands that let AI tools make safe vault decisions from metadata only.

**Architecture:** Extend the existing JSON metadata layer in `vault_tool.py`. `collect_vault_assessment()` combines `collect_vault_info()` and `collect_doctor_info()` into risks and recommended actions. `collect_vault_plan()` chooses one deterministic next action from the assessment. CLI integration follows the existing `info --json` and `doctor --json` pattern.

**Tech Stack:** Python 3 standard library, existing `unittest` suite, no new dependencies.

## Global Constraints

- Do not change VAULT01/VAULT02/VAULT03 file formats.
- Do not read, decrypt, print, or write plaintext.
- Do not accept passwords through CLI args, environment variables, stdin, or files.
- Do not list source or decrypted filenames in AI-safe JSON.
- Keep Windows zero-third-party-dependency behavior.
- Keep all JSON output safe for public logs and AI orchestration.

---

### Task 1: Add Red Tests for AI-safe Assessment and Plan

**Files:**
- Modify: `E:\Projects\Tools\vault-tool\test_vault_tool.py`

**Interfaces:**
- Consumes: `vault_tool.main(["assess", "--json"])`
- Consumes: `vault_tool.main(["plan", "--json"])`
- Produces: failing tests for JSON commands and safety fields.

- [ ] **Step 1: Add tests**

Add methods to `TestJsonMetadataCli`:

```python
def test_assess_json_reports_safe_contract_and_missing_vault(self):
    data = self.run_json("assess", "--json")
    self.assertTrue(data["ok"])
    self.assertEqual(data["mode"], "assess")
    self.assertTrue(data["safe_for_ai"])
    self.assertFalse(data["password_seen_by_ai"])
    self.assertFalse(data["plaintext_read"])
    self.assertFalse(data["plaintext_written"])
    self.assertFalse(data["decryption_attempted"])
    self.assertIn("vault_missing", {r["code"] for r in data["risks"]})
    self.assertIn("create_source", {a["action"] for a in data["recommended_actions"]})
    self.assert_ai_safe(data)
```

```python
def test_assess_json_does_not_leak_source_or_decrypted_filenames(self):
    vault_tool.SOURCE_DIR.mkdir()
    vault_tool.DECRYPTED_DIR.mkdir()
    (vault_tool.SOURCE_DIR / "production-api-token.txt").write_text("marker-source-secret", encoding="utf-8")
    (vault_tool.DECRYPTED_DIR / "password.txt").write_text("marker-decrypted-secret", encoding="utf-8")
    data = self.run_json("assess", "--json")
    text = json.dumps(data, ensure_ascii=False)
    self.assertNotIn("production-api-token", text)
    self.assertNotIn("password.txt", text)
    self.assertNotIn("marker-source-secret", text)
    self.assertNotIn("marker-decrypted-secret", text)
    self.assertIn("stale_decrypted_dir", {r["code"] for r in data["risks"]})
```

```python
def test_plan_json_recommends_migrate_for_vault02(self):
    vault_tool.VAULT_FILE.write_bytes(vault_tool._pack_vault("pw", b"legacy"))
    data = self.run_json("plan", "--json")
    self.assertTrue(data["ok"])
    self.assertEqual(data["mode"], "plan")
    self.assertEqual(data["decision"], "migrate")
    self.assertTrue(data["requires_password"])
    self.assert_ai_safe(data)
```

- [ ] **Step 2: Verify RED**

Run:

```powershell
python test_vault_tool.py
```

Expected: FAIL because `assess` and `plan` commands do not exist.

### Task 2: Implement Assessment Functions

**Files:**
- Modify: `E:\Projects\Tools\vault-tool\vault_tool.py`

**Interfaces:**
- Produces: `collect_vault_assessment(base=None) -> dict`
- Produces: risk objects `{code, severity, message}`
- Produces: action objects `{action, reason, requires_password}`

- [ ] **Step 1: Add AI-safe base helper**

Add:

```python
def _ai_safe_contract(mode):
    return {
        "ok": True,
        "mode": mode,
        "safe_for_ai": True,
        "password_seen_by_ai": False,
        "plaintext_read": False,
        "plaintext_written": False,
        "decryption_attempted": False,
    }
```

- [ ] **Step 2: Add risk/action helpers**

Add small constructors:

```python
def _risk(code, severity, message):
    return {"code": code, "severity": severity, "message": message}

def _action(action, reason, requires_password=False):
    return {"action": action, "reason": reason, "requires_password": bool(requires_password)}
```

- [ ] **Step 3: Add `collect_vault_assessment`**

Combine `collect_vault_info()` and `collect_doctor_info()`. Inspect only booleans,
formats, KDF metadata, file size, and dependency availability. Do not list any
directory contents.

- [ ] **Step 4: Verify targeted tests**

Run:

```powershell
python test_vault_tool.py TestJsonMetadataCli
```

Expected: tests still fail until CLI parser is wired.

### Task 3: Implement Plan Function and CLI Wiring

**Files:**
- Modify: `E:\Projects\Tools\vault-tool\vault_tool.py`
- Modify: `E:\Projects\Tools\vault-tool\README.md`

**Interfaces:**
- Produces: `collect_vault_plan(base=None) -> dict`
- CLI: `python vault_tool.py assess --json`
- CLI: `python vault_tool.py plan --json`

- [ ] **Step 1: Add `collect_vault_plan`**

Decision priority:

1. `manual_review` for `unknown_vault_format` or `old_default_path`.
2. `clean_decrypted` for `stale_decrypted_dir`.
3. `migrate` for `legacy_vault_format`.
4. `encrypt` for `source_ready`.
5. `inspect_or_decrypt` for a recognized existing vault.
6. `create_source` otherwise.

- [ ] **Step 2: Wire CLI**

Add `assess` and `plan` subcommands with `--json`. Include both in `json_mode`.
Print JSON when requested; print compact human summaries otherwise.

- [ ] **Step 3: Update README CLI section**

Add:

```bash
python vault_tool.py assess --json
python vault_tool.py plan --json
```

Explain these are metadata-only and safe for AI orchestration.

- [ ] **Step 4: Verify targeted tests**

Run:

```powershell
python test_vault_tool.py TestJsonMetadataCli
```

Expected: PASS.

### Task 4: Full Verification and Closeout

**Files:**
- Verify: `E:\Projects\Tools\vault-tool`

**Interfaces:**
- No side-effecting command beyond normal git commit/push.

- [ ] **Step 1: Full tests**

```powershell
python test_vault_tool.py
```

- [ ] **Step 2: Compile check**

```powershell
python -m py_compile vault_tool.py test_vault_tool.py
```

- [ ] **Step 3: CLI smoke**

```powershell
python vault_tool.py assess --json
python vault_tool.py plan --json
```

- [ ] **Step 4: Sensitive scan**

```powershell
rg -n "BEGIN\s+PRIVATE\s+KEY|g[h]p_|github[_]pat_|OPENAI[_]API[_]KEY|s[k]-[A-Za-z0-9]{8,}" vault_tool.py test_vault_tool.py README.md docs
```

Expected: no secrets.

- [ ] **Step 5: Commit and push**

```powershell
git add vault_tool.py test_vault_tool.py README.md docs/superpowers
git commit -m "feat: add AI-safe vault assessment commands"
git push
```
