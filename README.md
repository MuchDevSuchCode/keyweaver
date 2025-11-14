# KeyWeaver  
### *Deterministic Two-Passphrase Cryptographic Key Generator*

---

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Security](https://img.shields.io/badge/security-crypto-brightgreen.svg)
![Build](https://img.shields.io/badge/status-stable-success.svg)

KeyWeaver is a deterministic, high-security key generator designed for systems like **VeraCrypt**, secure backups, or any environment where a **repeatable** but **strong** key must be derived from **two independent passphrases**.

KeyWeaver combines modern hashing (SHA3 + BLAKE2), a two-secret XOR mixing strategy, and industry-standard KDFs (PBKDF2, scrypt, and Argon2id).  
The result is a hardened, wallet-style key generator suitable for serious cryptographic use.

---

## ✨ Features

- 🔐 **Two-passphrase input** for dual-factor secret derivation  
- 🧮 **Modern hash combiner:**  
  - `SHA3-256(secret)`  
  - `BLAKE2b-256(secret, personalization)`  
  - Combined via XOR  
- 🧱 **Multiple modern KDFs:**  
  - **PBKDF2-HMAC-SHA512** (portable, legacy compatible)  
  - **scrypt** (memory-hard, GPU-resistant)  
  - **Argon2id** (PHC winner, modern best practice)  
- 💾 **Output modes:**  
  - Full 128-byte key  
  - VeraCrypt 32-byte compatible key  
  - Raw binary keyfile output  
- 📋 Optional clipboard copy  
- 🔇 Quiet mode for scripting  
- 🛡️ Passphrase strength warning  
- 🧩 Fully deterministic: same inputs → same outputs  
- 🐧 macOS, Linux, Windows, and WSL compatible  

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/keyweaver.git
cd keyweaver
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

Your `requirements.txt`:

```text
argon2-cffi>=23.1.0
```

Argon2id is optional — PBKDF2 and scrypt work without it — but recommended.

---

## 🚀 Usage

Run the program:

```bash
python3 keyweaver.py
```

You will be asked for:

- **Passphrase #1**
- **Passphrase #2**  
  (each entered twice to confirm)

A key will be derived and printed or written to a file depending on mode.

---

# 🔧 Command Line Options

## KDF Selection

### PBKDF2 (default)

```bash
--kdf pbkdf2
--pbkdf2-iter 600000
```

### scrypt

```bash
--kdf scrypt
--scrypt-n 16384
--scrypt-r 8
--scrypt-p 1
```

### Argon2id (modern recommended)

```bash
--kdf argon2id
--argon2-m 65536      # memory cost in KiB (64 MiB)
--argon2-t 3          # time cost
--argon2-p 1          # parallelism
```

To use Argon2id, ensure `argon2-cffi` is installed.

---

## Output Modes

### Full 128-byte key (256 hex chars)

```bash
--output-mode full
```

### VeraCrypt-compatible 32-byte key (64 hex chars)

```bash
--veracrypt
```

or:

```bash
--output-mode veracrypt
```

### Write raw binary keyfile

```bash
--output-mode keyfile --keyfile path/to/keyfile.bin
```

The keyfile will contain the raw derived key bytes.

---

## Clipboard Mode

```bash
--copy
```

Copies the derived key to the system clipboard instead of printing it.

Works on:

- Linux (with `xclip` or `xsel`)
- macOS (`pbcopy`)
- Windows (`clip`)
- WSL (`clip.exe`)

Not available in `keyfile` mode (there is no textual key to copy).

---

## Quiet Mode

```bash
--quiet
```

Suppresses banners and warnings.  

- In normal modes: prints **only** the final key.  
- With `--copy`: prints only a short success message.

---

# 🧠 How It Works

## 1. Two-passphrase secret mixing

Each passphrase independently produces:

```text
SHA3-256(passphrase)                    → 32 bytes
BLAKE2b-256(passphrase, "VC2_PX")       → 32 bytes
---------------------------------------------------
Per-passphrase block                    → 64 bytes
```

Where `"VC2_P1"` and `"VC2_P2"` are distinct personalization strings.

The two 64-byte blocks are then XOR-combined:

```text
combined_block = block1 XOR block2   # 64 bytes total (512 bits)
```

So the intermediate secret is symmetric in both passphrases and depends on:

- Two different hash constructions (SHA3 + BLAKE2b)
- Two independent secrets
- Domain-separated personalization

If at least one passphrase is strong and at least one hash behaves well, the combined block remains strong.

---

## 2. Run the combined block through a KDF

Depending on the `--kdf` selection:

### PBKDF2-HMAC-SHA512

- Well-known and widely supported.
- Not memory-hard, but compatible with many environments.

### scrypt

- Memory-hard, more expensive to attack with GPUs and ASICs.
- Good upgrade over PBKDF2 where available.

### Argon2id (Recommended)

- Winner of the Password Hashing Competition.
- Hybrid defense: side-channel hardened and GPU-resistant.
- Tunable time, memory, and parallelism parameters.

In all cases, the KDF uses a **deterministic salt** derived from the combined block and a domain string, so that:

```text
same passphrases + same KDF + same parameters → same key
```

Final key length: **128 bytes** by default.

---

## 3. Output Result

Depending on the output mode:

- **Full (default)**: 128-byte key as a 256-character hex string.  
- **VeraCrypt mode**: first 32 bytes (64 hex chars) of the key.  
- **Keyfile mode**: raw 128-byte key written to disk as a binary file.

---

# 🔒 Security Considerations

- **Passphrase strength matters.**  
  The tool will warn about clearly weak passphrases, but entropy is ultimately on the user.  
  Use long, high-entropy, non-reused passphrases.

- **Two-passphrase design is not “magic 2FA.”**  
  It’s still just secrets → key derivation.  
  However, it does hedge by requiring two independent secrets.

- **Keyfiles are sensitive.**  
  Treat them like private keys or passwords: encrypt, back up, and restrict access.

- **Deterministic design is deliberate.**  
  This tool is **not** a password storage system. It is a **deterministic key generator**:
  - Good for reproducible keys, vaults, or recovery setups.
  - Not appropriate as a drop-in password hasher for user accounts.

---

# 🧪 Example Commands

### Generate VeraCrypt password using Argon2id

```bash
python3 keyweaver.py --kdf argon2id --veracrypt
```

### Generate full key and copy to clipboard

```bash
python3 keyweaver.py --kdf scrypt --copy
```

### Create a binary keyfile

```bash
python3 keyweaver.py --output-mode keyfile --keyfile secret.key
```

### High-memory Argon2id configuration

```bash
python3 keyweaver.py --kdf argon2id --argon2-m 262144 --argon2-t 4 --argon2-p 2
```

---

# 📁 Project Structure

```text
keyweaver.py       # Main CLI tool
requirements.txt   # Python dependencies
README.md          # This documentation
```

---

# 📜 License

This project is licensed under the **MIT License**.  
You are free to use, modify, and distribute it, subject to the terms of the license.

---

# 🙌 Contributions

Pull requests and suggestions are welcome.

Ideas for contributions:

- Add test vectors and self-test mode
- Benchmark different KDF parameters
- Add configuration presets (e.g. "laptop", "server", "HSM")
- Package as a Python module with an importable API

Happy key weaving. 🔑🧶
