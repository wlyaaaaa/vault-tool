# AI-safe Control Plane Design

## Goal

Add a read-only AI-safe control plane so assistants can inspect vault state,
assess risks, and recommend the next action without seeing passwords,
keyfile material, decrypted contents, source filenames, or plaintext residue.

## Scope

In scope:

- Add `assess --json` for read-only state/risk assessment.
- Add `plan --json` for deterministic next-action recommendations.
- Reuse existing `collect_vault_info()` and `collect_doctor_info()` metadata.
- Keep the interface safe for public logs and AI orchestration.
- Test that no password, keyfile hash, plaintext body, source filename, or
  decrypted filename is exposed.

Out of scope:

- New encryption format or KDF changes.
- Automatic encryption/decryption.
- Passing passwords through CLI args, environment variables, stdin, or files.
- Reading or decrypting vault contents.
- Key-repository-specific decisions.

## Safety Contract

Every AI-safe control-plane JSON object must include:

- `safe_for_ai: true`
- `password_seen_by_ai: false`
- `plaintext_read: false`
- `plaintext_written: false`
- `decryption_attempted: false`

The commands may read metadata such as file existence, file size, vault format,
KDF parameters, dependency availability, and directory existence. They must not
list source or decrypted filenames because filenames may themselves be secrets.

## Assessment Behavior

`assess --json` returns:

- `ok`: whether the assessment ran.
- `mode`: `assess`.
- `vault`: result from `collect_vault_info()`.
- `environment`: result from `collect_doctor_info()`.
- `risks`: list of objects with `code`, `severity`, and `message`.
- `recommended_actions`: ordered list of action objects with `action`,
  `reason`, and `requires_password`.

Initial risk codes:

- `vault_missing`: no `vault.enc` exists.
- `legacy_vault_format`: vault is VAULT01 or VAULT02.
- `unknown_vault_format`: vault header is unrecognized or malformed.
- `keyfile_not_required`: VAULT03 exists but does not require a keyfile.
- `stale_decrypted_dir`: `decrypted/` exists and should be cleaned.
- `source_ready`: `source/` exists, so encryption may be the next action.
- `old_default_path`: base path is the deprecated `E:\Vault`.
- `argon2_unavailable`: Argon2id support is unavailable.

Severity values are `info`, `warning`, or `critical`.

## Plan Behavior

`plan --json` wraps the assessment and chooses one top-level decision:

- `encrypt`: source exists and no blocking issue is present.
- `migrate`: existing vault is VAULT01 or VAULT02.
- `inspect_or_decrypt`: existing modern vault is present.
- `clean_decrypted`: stale decrypted directory exists.
- `create_source`: neither source nor vault exists.
- `manual_review`: unknown/malformed vault or deprecated path.

The plan must never execute the action. It only tells an AI or user what the
next local command should be.

## Testing

Use the existing `unittest` suite. Tests should monkeypatch project globals to
a temporary directory and call `vault_tool.main(["assess", "--json"])` /
`vault_tool.main(["plan", "--json"])`.

Test cases:

- Missing vault and missing source recommends `create_source`.
- Source exists recommends `encrypt`.
- VAULT02 recommends `migrate`.
- VAULT03 without keyfile emits `keyfile_not_required` warning.
- Existing `decrypted/` emits `stale_decrypted_dir` and recommends cleanup.
- JSON output does not leak source/decrypted filenames or plaintext marker text.

## Acceptance Criteria

- `python test_vault_tool.py` passes.
- `python vault_tool.py assess --json` emits one JSON object and has no side
  effects.
- `python vault_tool.py plan --json` emits one JSON object and has no side
  effects.
- `python -m py_compile vault_tool.py test_vault_tool.py` passes.
- Sensitive-pattern scans do not find passwords, private keys, tokens, or
  plaintext fixture markers in committed control-plane output.
