# Key Weaver – Two-Passphrase Deterministic Key Generator for VeraCrypt

A small command-line tool that deterministically derives high-entropy key material from **two independent passphrases**, suitable for use with **VeraCrypt** (as a password or keyfile) or any other system that accepts raw keys / hex strings.

Same passphrases + same KDF settings ⇒ **exactly the same key** every time.

> ⚠️ This tool handles cryptographic secrets. Treat its output like a live grenade made of math.

---

## Features

- 🔑 **Two-passphrase design**  
  Combines two independent passphrases into a single 128-byte key.

- ♻️ **Deterministic output**  
  Same inputs + same KDF parameters always produce the same key or keyfile.

- 🧮 **Modern KDFs**  
  - `PBKDF2-HMAC-SHA512` (default, configurable iterations)  
  - `scrypt` (memory-hard, tunable N/r/p)

- 🎛 **Flexible output modes**
  - Full 256-character hex key (128 bytes)
  - VeraCrypt-style 64-character hex string (32 bytes – max VC password length)
  - Raw binary keyfile, suitable as a VeraCrypt keyfile

- 📋 **Clipboard support**  
  Copy the key directly to the system clipboard (Linux/macOS/Windows/WSL).

- 🧠 **Weak passphrase warnings**  
  Very rough entropy estimate; warns you if your passphrases look weak.

---

## Quick Start

```bash
# Default: PBKDF2, full 256-char hex key printed to stdout
python3 Key Weaver.py
```

You will be prompted:

- `Passphrase #1` (with confirmation)
- `Passphrase #2` (with confirmation)

Then the derived key is shown:

```text
=== DERIVED KEY ===
<256 hex characters here>
===================
```

---

## Installation

1. Save the script as `Key Weaver.py` (or whatever name you prefer).
2. Ensure you have Python 3 installed (3.8+ recommended).
3. Make it executable (optional, Unix-like systems):

   ```bash
   chmod +x Key Weaver.py
   ```

4. Run it:

   ```bash
   ./Key Weaver.py        # Unix-like
   # or
   python3 Key Weaver.py  # any OS
   ```

No external Python dependencies are required; everything uses the standard library.

---

## How It Works (High Level)

1. You enter **two passphrases**, each confirmed.
2. The tool computes:

   ```text
   preimage = SHA-512(passphrase_1) || SHA-512(passphrase_2)
   ```

3. A deterministic salt is derived from this preimage and a context tag:
   - For PBKDF2: `"VC2PBKDF2"`
   - For scrypt: `"VC2SCRYPT"`

4. The chosen KDF (PBKDF2 or scrypt) derives **128 bytes** of key material.
5. Depending on output mode, the key is:
   - Printed as hex (256 chars / 128 bytes),
   - Truncated to the first 64 hex chars (32 bytes) for VeraCrypt,
   - Or written as a **binary keyfile**.

Intermediate buffers are overwritten (best-effort in Python) once they’re no longer needed.

---

## Usage

### Basic Usage (Default)

```bash
python3 Key Weaver.py
```

- KDF: PBKDF2-HMAC-SHA512
- Iterations: 600000
- Output: 256-character hex key printed to stdout

---

### VeraCrypt-Style Password Mode

Produce a 64-character hex string (32 bytes), which matches VeraCrypt’s maximum password length:

```bash
python3 Key Weaver.py --output-mode veracrypt
# or the shorthand:
python3 Key Weaver.py --veracrypt
```

Use the printed 64-character string as your VeraCrypt volume password.

---

### Keyfile Mode

Generate a **binary keyfile**:

```bash
python3 Key Weaver.py --output-mode keyfile --keyfile my_vc.key
```

- Writes 128 raw key bytes to `my_vc.key`.
- The file must **not already exist** – the tool refuses to overwrite it.
- The actual key material is **not printed** (by design).

To recreate the same keyfile later:

- Use **the same two passphrases**, and  
- Use **the same KDF options** (`--kdf`, `--pbkdf2-iter` OR `--scrypt-*`).

---

### Clipboard Mode

Copy the derived key to the clipboard without printing it to stdout:

```bash
# Example: get a 64-char VeraCrypt password into clipboard
python3 Key Weaver.py --veracrypt --copy
```

Behavior:

- On **WSL**: uses `clip.exe`
- On **Windows**: uses `clip`
- On **macOS**: uses `pbcopy`
- On **Linux desktop**: uses `xclip` or `xsel` if available

If clipboard integration fails, an error is shown and the process exits.

> Note: `--copy` cannot be used with `--output-mode keyfile` (there is nothing textual to copy).

---

## Command-Line Options

### KDF Selection

```bash
--kdf {pbkdf2,scrypt}
```

- `pbkdf2` – Default. Uses PBKDF2-HMAC-SHA512.
- `scrypt` – Memory-hard KDF with tunable parameters.

#### PBKDF2 Options

```bash
--pbkdf2-iter N
```

- Default: `600000` iterations.
- Larger values = slower but stronger against brute force.

#### scrypt Options

```bash
--scrypt-n N
--scrypt-r R
--scrypt-p P
```

Defaults:

- `--scrypt-n 16384`  (2^14)
- `--scrypt-r 8`
- `--scrypt-p 1`

On constrained systems, large parameters may yield a `memory limit exceeded` or similar error. In that case, try:

```bash
python3 Key Weaver.py --kdf scrypt \
  --scrypt-n 4096 --scrypt-r 4 --scrypt-p 1
```

---

### Output Modes

```bash
--output-mode {full,veracrypt,keyfile}
```

| Mode        | Description                                            | Size                      |
|------------|--------------------------------------------------------|---------------------------|
| `full`     | 256 hex chars (128 bytes of key material)              | 256 hex characters        |
| `veracrypt`| First 64 hex chars of the full key (VeraCrypt-friendly)| 64 hex characters (32 B)  |
| `keyfile`  | Raw 128-byte key written directly to a binary file     | 128 bytes (binary file)   |

Shorthand:

```bash
--veracrypt  # equivalent to --output-mode veracrypt
```

Keyfile-specific:

```bash
--keyfile PATH
```

Required when using `--output-mode keyfile`.

---

### Behavior Flags

```bash
--copy
```

- Copy the derived key to clipboard instead of printing it.
- Not allowed with `--output-mode keyfile`.

```bash
--quiet
```

- Suppresses banners and extra commentary.
- In hex/VC modes: prints *only* the key.
- With `--copy`: prints only a minimal success message.

```bash
--no-warnings
```

- Suppresses startup safety warnings.
- **Note:** This does *not* suppress weak-passphrase warnings; those are tied to the prompts.

---

## Passphrase Strength Warnings

The tool estimates passphrase strength using:

- Detected character sets (lowercase, uppercase, digits, symbols)
- Length of the passphrase
- Rough entropy formula: `entropy ≈ length * log2(charspace)`

If a passphrase:

- Is shorter than 16 characters, **or**
- Has estimated entropy < ~80 bits,

…you’ll see a warning like:

```text
WARNING:
  Passphrase #1 appears weak.
  Length: 12 characters
  Estimated entropy: ~52.4 bits
  Consider a longer, more random passphrase.
```

This is a **rough** heuristic, not a formal password auditor.

---

## Security Notes

- Anyone who learns:
  - Either passphrase, **or**
  - The derived hex key, **or**
  - The keyfile contents

  …can decrypt anything that uses that key.

- Ensure your passphrases are:
  - Long  
  - Unique (not reused anywhere else)  
  - High entropy (avoid dictionary phrases and clichés)

- Keyfiles:
  - Are written to disk; treat them like any other master secret.
  - Back them up securely if you’re relying on deterministic regeneration.

- The tool makes a best effort to scrub sensitive data from memory (e.g. the preimage buffer), but Python cannot guarantee full memory sanitization.

- Clipboard use is convenient but risky on shared systems. Other processes or clipboard history tools might read it.

---

## Determinism & Reproducibility

The derived key depends on **all** of the following:

- Passphrase #1 (exact string, including case and spacing)
- Passphrase #2
- KDF choice: `pbkdf2` vs `scrypt`
- PBKDF2 iteration count **or** scrypt parameters (N, r, p)
- Hardcoded context strings (`b"VC2PBKDF2"` / `b"VC2SCRYPT"`)

If any of these change, the key changes.

If all are identical, the derived key and keyfile are reproducible across machines and time (assuming the same version of the script and Python’s KDF implementations).

---

## Exit Codes

- `0` – Success
- `1` – Misuse or runtime error:
  - Invalid CLI combination
  - Failed clipboard copy
  - Failed keyfile write
  - scrypt failure (e.g., memory constraints)
- `1` – Also used when the user aborts with `Ctrl+C` (KeyboardInterrupt)

---

## Disclaimer

- This tool is **not** affiliated with VeraCrypt or its authors.
- No cryptographic tool can save you from weak passphrases or bad opsec.
- Use at your own risk; review the source code and threat model for your use case.

---

## Detailed Description of the App (Design & Behavior)

This section is more of an architectural / conceptual walkthrough than user-facing docs.

### Core Idea

The app’s job is to turn **two passphrases** into **high-entropy key material** in a way that is:

- **Deterministic** – same inputs ⇒ same output
- **Configurable** – adjustable KDF parameters
- **Tool-friendly** – output can be used:
  - As a VeraCrypt password (64 hex chars),
  - As a raw keyfile,
  - Or as a generic cryptographic key in other contexts.

Using two passphrases lets you:

- Split responsibility (e.g., two people each know one passphrase).
- Combine a “memorized” passphrase with something written down.
- Upgrade security by stretching two independent secrets into one strong key.

---

### Preimage Construction

Internally, the app never feeds your plain passphrases directly into the KDF.

Instead, it builds a **preimage**:

1. Compute SHA-512 of each passphrase (UTF-8 encoded):

   ```python
   h1 = hashlib.sha512(pass1.encode("utf-8")).digest()
   h2 = hashlib.sha512(pass2.encode("utf-8")).digest()
   ```

2. Concatenate them into a `bytearray`:

   ```python
   preimage = bytearray(h1 + h2)
   ```

3. The original `pass1`, `pass2`, `h1`, and `h2` variables are nulled (best effort).

This `preimage` is what the KDF actually sees.

Why do it this way?

- It normalizes the passphrases into fixed-length, high-diffusion blobs.
- It avoids giving the KDF two separate inputs; everything is folded into one 1024-bit chunk.

---

### Deterministic Salt Strategy

The app uses a **salt**, but not a random one. It derives the salt deterministically from:

- The preimage, and  
- A context label that encodes the KDF type.

For PBKDF2:

```python
context = b"VC2PBKDF2"
pre_hash = hashlib.sha512(preimage).digest()
salt = hashlib.sha512(context + pre_hash).digest()
```

For scrypt, same idea but `context = b"VC2SCRYPT"`.

This gives you:

- Isolation between different KDFs (PBKDF2 and scrypt won’t collide).
- A salt that is *truly derived* from the passphrases, yet stable and deterministic.

The cost: there is no random per-instance salt, because reproducibility is the priority.

---

### KDF Engines

#### PBKDF2 (`derive_key_pbkdf2`)

- Uses `hashlib.pbkdf2_hmac("sha512", ...)`.
- Iteration count default: 600,000, configurable via `--pbkdf2-iter`.
- Output length: 128 bytes (`DEFAULT_KEY_LEN_BYTES`).

PBKDF2 is CPU-hard only—solid, widely supported, but not memory-hard.

#### scrypt (`derive_key_scrypt`)

- Uses `hashlib.scrypt(...)` with user-tunable parameters.
- Default parameters: N=2^14, r=8, p=1.
- Also outputs 128 bytes.

If scrypt fails (e.g., due to memory constraints), the code:

- Prints an error message,
- Suggests smaller parameters when the error mentions “memory”,
- Scrubs the preimage before re-raising the exception.

---

### Memory Hygiene

Python isn’t a low-level, constant-time cryptographic environment, but the app still tries to be reasonably hygienic:

- Preimage buffer is a mutable `bytearray`.
- After key derivation, all bytes are overwritten with zero:

  ```python
  for i in range(len(preimage)):
      preimage[i] = 0
  preimage = None
  ```

- Passphrase variables are nulled (`pass1 = pass2 = None`) as soon as they’re no longer needed.

This doesn’t guarantee that all traces vanish from memory (GC, copies, internal buffers are outside user control), but it’s better than leaving sensitive data lying around in long-lived Python objects.

---

### Passphrase Strength Estimation

`estimate_passphrase_strength` uses a very naive model:

1. Infer the size of the character set used in the passphrase:
   - Add 26 if any lowercase letters are present.
   - Add 26 if any uppercase letters are present.
   - Add 10 if digits are present.
   - Add 32 for “symbols” (non-alphanumeric).

2. If for some reason it can’t classify anything, it assumes 95 printable ASCII characters.

3. Entropy is estimated as:

   ```python
   entropy_bits ≈ len(pw) * log2(charspace)
   ```

4. If:
   - `len(pw) < 16`, or
   - `entropy_bits < 80`

   …the tool prints a warning for that passphrase label.

This is intentionally “loud but not strict.” It won’t block you, it just nudges you toward longer, more random passphrases.

---

### Clipboard Handling

`copy_to_clipboard` tries to be cross-platform:

- First checks if we’re under WSL by reading `/proc/version` and looking for “microsoft”.
- Then chooses the appropriate backend:
  - WSL: `clip.exe`
  - macOS: `pbcopy`
  - Windows: `clip`
  - Linux: `xclip` or `xsel`, if available

It returns a boolean indicating success, so the caller can decide whether to bail with an error.

If clipboard copy succeeds:

- The key is **not** printed to stdout.
- In non-quiet mode, a confirmation message is printed.

---

### CLI Flow & Validation

`parse_args` wires up all the flags and provides:

- KDF selection and parameters
- Output modes and shortcuts
- Keyfile path
- Behavior flags (`--copy`, `--quiet`, `--no-warnings`)

`main()` then:

1. Validates incompatible or incomplete combinations:
   - `--output-mode keyfile` requires `--keyfile PATH`.
   - `--copy` is disallowed with `--output-mode keyfile`.

2. Prints startup warnings unless `--no-warnings` or `--quiet` is set.

3. Prompts for `Passphrase #1` and `Passphrase #2`, each twice.

4. Warns if the two passphrases are identical.

5. Derives the key using the chosen KDF and parameters.

6. Based on `output_mode`:
   - `keyfile`: write raw bytes to disk; show summary.
   - `full` / `veracrypt`:
     - Convert to hex, optionally truncate, then either:
       - Copy to clipboard (`--copy`), or
       - Print to stdout (with or without banners depending on `--quiet`).

7. Handles `KeyboardInterrupt` gracefully and exits with code 1.

---

In short: this app is a compact, deterministic “key factory” that uses two passphrases as raw material, runs them through SHA-512 + PBKDF2 or scrypt, and gives you either a hex string or a keyfile suitable for VeraCrypt and similar tools—while nagging you gently if your passphrases look weak.
