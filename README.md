# KeyWeaver

### Two-Passphrase Deterministic Cryptographic Key Generator

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Status](https://img.shields.io/badge/status-stable-success.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20WSL-lightgrey)

KeyWeaver derives **the same high-entropy key from the same two passphrases, every time**. It is built for use cases such as VeraCrypt volumes, encrypted backups, and any workflow where you want a strong key that you can re-derive from memory rather than store on disk.

Two independent secrets are mixed through SHA3-256 + BLAKE2b with domain separation, XOR-combined, and stretched through a memory-hard KDF (PBKDF2-SHA512, scrypt, or Argon2id).

---

## Table of Contents

- [Why two passphrases?](#why-two-passphrases)
- [Quick start](#quick-start)
- [Threat model](#threat-model)
- [Installation](#installation)
- [CLI usage](#cli-usage)
- [GUI usage](#gui-usage)
- [Output modes](#output-modes)
- [KDF parameter guidance](#kdf-parameter-guidance)
- [How it works](#how-it-works)
- [Determinism contract](#determinism-contract)
- [Security considerations](#security-considerations)
- [FAQ](#faq)
- [License](#license)

---

## Why two passphrases?

A single passphrase is a single point of failure: forget it and the data is gone; leak it and the data is exposed.

Two passphrases let you split that risk. Common patterns:

- **Memorise one, store one** — keep one in your head, the other in a secure secondary location (paper safe, HSM, second password manager). Compromise of either alone yields nothing.
- **Personal + corporate** — one passphrase is yours, one belongs to your team. Both must be present to derive the key.
- **Pure memory** — two long passphrases, both memorised, with stronger combined entropy than either alone.

KeyWeaver is fully deterministic: the same two passphrases (in the same order, with the same KDF parameters) always produce the same key. There is no salt to lose, no keyfile to back up — only the recipe.

---

## Quick start

```bash
# Clone and install
git clone https://github.com/MuchDevSuchCode/KeyWeaver.git
cd keyweaver
pip install -r requirements.txt

# CLI — derive a 32-byte VeraCrypt key with PBKDF2 (default)
python keyweaver.py --veracrypt

# CLI — same passphrases, Argon2id, copy to clipboard, auto-clear in 30s
python keyweaver.py --kdf argon2id --copy --fingerprint

# GUI
python keyweaver_gui.py
```

---

## Threat model

KeyWeaver protects against:

- **Disclosure of one passphrase.** An attacker who learns only `p1` or only `p2` cannot derive the key — they would still need to brute-force the other passphrase against the KDF cost.
- **Offline brute-force on a stored keyfile.** Not applicable — there is no stored secret in the default workflow.
- **Cross-context reuse.** Personalization strings (`VC2_P1`, `VC2_P2`) and salt labels prevent one KeyWeaver-derived key from being reused as another via length-extension or related-secret attacks.

KeyWeaver does **not** protect against:

- **Compromise of the running process.** Memory dumps, debuggers, screen capture, or keyloggers all bypass any key-derivation tool.
- **Disclosure of both passphrases.** By design.
- **Disclosure of the derived key or keyfile.** Treat outputs as you would any cryptographic key.
- **Weak passphrases.** A 12-character lowercase passphrase is brute-forceable regardless of which KDF you pick. Use long, high-entropy, non-reused passphrases.

---

## Installation

### Requirements

- Python 3.8 or newer
- (Optional) `argon2-cffi` for Argon2id support

### Install

```bash
git clone https://github.com/MuchDevSuchCode/KeyWeaver.git
cd keyweaver
pip install -r requirements.txt
```

### Verify

```bash
python keyweaver.py --help
```

---

## CLI usage

```text
python keyweaver.py [options]
```

### Options

| Flag | Description |
|---|---|
| `--kdf {pbkdf2,scrypt,argon2id}` | KDF to use (default: `pbkdf2`). |
| `--pbkdf2-iter N` | PBKDF2 iteration count (default `600000`). |
| `--scrypt-n N` / `--scrypt-r R` / `--scrypt-p P` | scrypt cost parameters (default `16384` / `8` / `1`). |
| `--argon2-m KIB` / `--argon2-t T` / `--argon2-p P` | Argon2id parameters (default `65536` KiB / `3` / `1`). |
| `--output-mode {full,veracrypt,keyfile}` | Output format (default `full`). |
| `--veracrypt` | Shortcut for `--output-mode veracrypt`. |
| `--keyfile PATH` | Destination path for `--output-mode keyfile`. |
| `--copy` | Copy result to clipboard instead of printing. |
| `--copy-timeout SECONDS` | Auto-clear clipboard after N seconds (default `30`, `0` disables). |
| `--fingerprint` | Print an 8-byte BLAKE2 tag of the final key. Use it to verify you typed the right passphrases without revealing the key. |
| `--min-entropy BITS` | Refuse to proceed if either passphrase has fewer estimated bits than this. |
| `--force` | Override `--min-entropy` refusal. |
| `--quiet` | Print only the result. |
| `--no-warnings` | Suppress safety warnings. |

### Examples

Derive the default 128-byte hex key:

```bash
python keyweaver.py
```

Derive a VeraCrypt-compatible 32-byte hex key, Argon2id, with fingerprint:

```bash
python keyweaver.py --kdf argon2id --veracrypt --fingerprint
```

Write a binary keyfile (atomic, mode 0600 on Unix):

```bash
python keyweaver.py --kdf scrypt --output-mode keyfile --keyfile ~/secrets/vol1.key
```

Copy to clipboard with explicit 60-second auto-clear:

```bash
python keyweaver.py --kdf argon2id --copy --copy-timeout 60
```

Refuse to derive unless both passphrases meet a strength bar:

```bash
python keyweaver.py --min-entropy 100
```

---

## GUI usage

```bash
python keyweaver_gui.py
```

The GUI uses Tkinter (Python standard library — no extra dependencies). It exposes the same crypto primitives as the CLI through a single `derive_key()` entry point in `keyweaver.py`, so output is byte-for-byte identical given the same inputs.

Features:

- Two passphrase fields with confirmation and show/hide toggles
- Live entropy meter
- KDF selector with parameter spinboxes
- Output mode selector (full hex / VeraCrypt / binary keyfile)
- Copy-to-clipboard with 30-second auto-clear
- Fingerprint display for cross-verification
- "Wipe Result" button to clear the on-screen key

---

## Output modes

| Mode | Output | Bytes | Hex chars | Use case |
|---|---|---|---|---|
| `full` | hex string | 128 | 256 | Largest available; suitable for any purpose. |
| `veracrypt` | hex string | 32 | 64 | Drop-in for VeraCrypt's "Use keyfile as password" or AES-256 keys. |
| `keyfile` | binary file | 128 | — | Use directly as a VeraCrypt keyfile or any binary key input. |

---

## KDF parameter guidance

> **Determinism warning.** The defaults below are part of the **determinism contract**. If you derive a key today with default parameters and re-derive it next year with default parameters, the result is identical. If you change parameters in between, the result will differ — you must record the parameters you used.

| KDF | Default | Tighter (slower) | Comments |
|---|---|---|---|
| **PBKDF2-SHA512** | `--pbkdf2-iter 600000` | `2000000+` | Portable, stdlib-only. Vulnerable to GPU/ASIC parallelism. Use only when memory-hard KDFs are not available. |
| **scrypt** | `N=16384 r=8 p=1` (≈16 MiB) | `N=1048576 r=8 p=1` (≈1 GiB) | Memory-hard. Good GPU resistance. |
| **Argon2id** | `m=65536 t=3 p=1` (64 MiB) | `m=1048576 t=4 p=1` (1 GiB) | Modern best practice. Recommended for new deployments. |

**Pick your parameters once, write them down, never change them for a given key.** A sticky note that says "Argon2id m=262144 t=4 p=1" is harmless if intercepted — it tells an attacker nothing they could not derive themselves. Without it, however, you may not be able to reproduce your own key.

---

## How it works

```
   ┌────────────────┐         ┌────────────────┐
   │  Passphrase 1  │         │  Passphrase 2  │
   └───────┬────────┘         └────────┬───────┘
           │                           │
           ▼                           ▼
  SHA3-256(p1) ‖ BLAKE2b-256(p1, "VC2_P1")
  SHA3-256(p2) ‖ BLAKE2b-256(p2, "VC2_P2")
           │                           │
           └─────────────┬─────────────┘
                         ▼
                XOR  →  combined_block (64 bytes)
                         │
                         ▼
            KDF(combined_block, salt = SHA512(label ‖ combined_block),
                cost parameters)
                         │
                         ▼
                   final_key (128 bytes)
```

1. **Two-hash construction per passphrase.** SHA3-256 and BLAKE2b-256 are unrelated families, so a structural break in one does not propagate. Concatenation gives 64 bytes of mixed material per passphrase.
2. **Personalization.** BLAKE2b's `person` parameter is set to `VC2_P1` for passphrase one and `VC2_P2` for passphrase two. This guarantees that swapping the two passphrases produces a completely different result, and prevents accidental cross-context collisions.
3. **XOR combiner.** The two 64-byte blocks are XORed. As long as either block has full entropy on its own, the combined block is at least as strong as the stronger input.
4. **Deterministic salt.** The KDF salt is `SHA512(label || combined_block)`. This preserves determinism (no random salt to store) at the cost of giving the salt no independent entropy. Security therefore depends on passphrase entropy + KDF cost — exactly the assumption KDFs are designed for.
5. **KDF stretch.** PBKDF2, scrypt, or Argon2id is run over the combined block to produce the final 128-byte key.

---

## Determinism contract

These values must not change without a major version bump, because changing them silently breaks every key already derived:

- Personalization strings: `VC2_P1`, `VC2_P2`
- Salt labels: `VC2_PBKDF2_SALT`, `VC2_SCRYPT_SALT`, `VC2_ARGON2ID_SALT`
- Default KDF parameter values
- Default key length (128 bytes)
- VeraCrypt truncation (first 64 hex chars of the full key)

If you upgrade KeyWeaver, your derived keys remain stable as long as you continue to use the same KDF and parameters.

---

## Security considerations

- **Memory wiping is best-effort.** Python cannot reliably wipe immutable strings from RAM. Internal buffers are stored in `bytearray` and zeroed after use, but assume that anything you type may persist in memory until the process exits. For high-value workflows, consider running on a system with encrypted swap and locked memory pages.
- **Clipboard auto-clear is best-effort.** The CLI overwrites the clipboard with whitespace after the timeout; the GUI does the same via `Tk.after()`. Some clipboard managers retain history regardless. Disable clipboard history before using `--copy`.
- **Keyfiles are written with `O_EXCL` and mode `0600`.** The tool refuses to overwrite an existing file. On Windows, file mode is largely advisory; rely on directory ACLs.
- **Deterministic salts are intentional.** They preserve repeatability. They also mean every byte of "extra randomness" your scheme has must come from the passphrases themselves — pick accordingly.
- **The fingerprint is one-way.** It is a BLAKE2b-64 digest of the derived key with its own personalization string. Sharing the fingerprint between two re-derivations confirms they produced the same key without revealing it.

---

## FAQ

**Why not just use a password manager?**
You can. KeyWeaver is for the case where you specifically want *no stored secret* — only a procedure that two people, or one person across two contexts, can re-execute on demand.

**Does the order of passphrases matter?**
Yes. `(p1, p2)` and `(p2, p1)` produce different keys because of the personalization strings.

**What if I forget which KDF or parameters I used?**
Try them in turn — there are only a few. Compare the fingerprint against your records (the fingerprint is safe to write down).

**Is the deterministic salt a vulnerability?**
It is a deliberate design choice. Without random salt, an attacker who guesses your passphrases can verify the guess offline at full KDF cost — same as for any salted KDF where the salt is known. The only thing a random salt would add is protection against precomputed multi-target attacks, which is not relevant for personally-derived keys.

**Why three KDFs?**
PBKDF2 for portability and stdlib compatibility, scrypt for moderate memory hardness with stdlib support, Argon2id for modern best-practice memory hardness (requires `argon2-cffi`).

**Can I use this for password hashing?**
No. KeyWeaver is for *key derivation* — single user, deterministic, no random salt. For password hashing in a multi-user system, use Argon2id directly with per-user random salts.

---

## License

MIT — see `LICENSE`.
