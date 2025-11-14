#!/usr/bin/env python3
"""
Two-passphrase deterministic key generator for VeraCrypt.

OVERVIEW
========
This tool derives high-entropy key material from TWO independent passphrases.

High-level workflow:

  1. Prompt for Passphrase #1 (with confirmation)
  2. Prompt for Passphrase #2 (with confirmation)

  3. Build a 512-bit combined secret block from both passphrases:

       block_for_p1 = SHA3-256(p1) concatenated with
                      BLAKE2b-256(p1, personalization="VC2_P1")

       block_for_p2 = SHA3-256(p2) concatenated with
                      BLAKE2b-256(p2, personalization="VC2_P2")

       combined_block = XOR(block_for_p1, block_for_p2)

     Each passphrase is processed independently.
     Each uses two hash constructions.
     Personalization strings provide domain separation.

  4. Run KDF (PBKDF2-HMAC-SHA512, scrypt, or Argon2id) over the combined block:

         final_key = KDF(combined_block, deterministic_salt, ...)

  5. Output key material in hex or as a binary keyfile.

OUTPUT MODES
============

  --output-mode full        → full 128-byte key (256 hex chars)
  --output-mode veracrypt   → first 32 bytes (64 hex chars)
  --output-mode keyfile     → write raw key bytes to file

KDF OPTIONS
===========

  PBKDF2:
    --kdf pbkdf2 (default)
    --pbkdf2-iter N          (default 600000)

  scrypt:
    --kdf scrypt
    --scrypt-n N             (CPU/memory cost, default 2^14)
    --scrypt-r R             (block size, default 8)
    --scrypt-p P             (parallelism, default 1)

  Argon2id:
    --kdf argon2id
    --argon2-m MEM_KIB       (memory cost in KiB, default 65536 = 64 MiB)
    --argon2-t T             (time cost / iterations, default 3)
    --argon2-p P             (parallelism, default 1)

SECURITY NOTES
==============
  - Anyone who learns either passphrase, or the final key, can decrypt.
  - Use long, high-entropy, non-reused passphrases.
  - In keyfile mode, the keyfile must be protected like any secret.
"""

import argparse
import getpass
import hashlib
import math
import sys
import os
import subprocess
import shutil

# Argon2id (optional dependency)
try:
    from argon2.low_level import Type as Argon2Type, hash_secret_raw as argon2_hash_secret_raw
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_KEY_LENGTH_BYTES = 128
DEFAULT_PBKDF2_ITERATIONS = 600_000

DEFAULT_SCRYPT_N = 2**14
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1

# Argon2id defaults (memory in KiB)
DEFAULT_ARGON2_MEMORY_KIB = 64 * 1024   # 64 MiB
DEFAULT_ARGON2_TIME_COST = 3
DEFAULT_ARGON2_PARALLELISM = 1


# ---------------------------------------------------------------------------
# Passphrase Strength Warnings
# ---------------------------------------------------------------------------

def estimate_passphrase_entropy_bits(passphrase: str) -> float:
    if not passphrase:
        return 0.0

    charset_size = 0
    if any("a" <= c <= "z" for c in passphrase):
        charset_size += 26
    if any("A" <= c <= "Z" for c in passphrase):
        charset_size += 26
    if any("0" <= c <= "9" for c in passphrase):
        charset_size += 10
    if any(not c.isalnum() for c in passphrase):
        charset_size += 32
    if charset_size == 0:
        charset_size = 95

    return len(passphrase) * math.log2(charset_size)


def warn_if_passphrase_weak(passphrase: str, label: str) -> None:
    bits = estimate_passphrase_entropy_bits(passphrase)

    if len(passphrase) < 16 or bits < 80:
        print("WARNING:", file=sys.stderr)
        print(f"  {label} appears weak.", file=sys.stderr)
        print(f"  Length: {len(passphrase)} characters", file=sys.stderr)
        print(f"  Estimated entropy: {bits:.1f} bits\n", file=sys.stderr)


# ---------------------------------------------------------------------------
# Prompting
# ---------------------------------------------------------------------------

def prompt_for_passphrase(label: str) -> str:
    while True:
        passphrase_first = getpass.getpass(f"Enter {label}: ")
        passphrase_second = getpass.getpass(f"Re-enter {label}: ")

        if passphrase_first != passphrase_second:
            print("Passphrases do not match.\n", file=sys.stderr)
            continue
        if not passphrase_first:
            print("Passphrase cannot be empty.\n", file=sys.stderr)
            continue

        warn_if_passphrase_weak(passphrase_first, label)
        return passphrase_first


# ---------------------------------------------------------------------------
# Two-Passphrase SHA3+BLAKE2 Combiner
# ---------------------------------------------------------------------------

def build_two_passphrase_combined_block_sha3_blake2(passphrase_one: str, passphrase_two: str) -> bytes:
    """
    Returns a 512-bit block:

        XOR(
            SHA3-256(passphrase_one) || BLAKE2b-256(passphrase_one),
            SHA3-256(passphrase_two) || BLAKE2b-256(passphrase_two)
        )
    """
    def block_for_passphrase(passphrase: str, personalization: bytes) -> bytes:
        passphrase_bytes = passphrase.encode("utf-8")

        sha3_part = hashlib.sha3_256(passphrase_bytes).digest()
        blake2_part = hashlib.blake2b(
            passphrase_bytes,
            digest_size=32,
            person=personalization,
        ).digest()

        return sha3_part + blake2_part

    block_one = block_for_passphrase(passphrase_one, b"VC2_P1")
    block_two = block_for_passphrase(passphrase_two, b"VC2_P2")

    combined_block = bytes(a ^ b for a, b in zip(block_one, block_two))

    return combined_block


# ---------------------------------------------------------------------------
# KDF layers
# ---------------------------------------------------------------------------

def derive_final_key_with_pbkdf2(combined_block: bytes, iterations: int, output_length_bytes: int) -> bytes:
    salt = hashlib.sha512(b"VC2_PBKDF2_SALT" + combined_block).digest()

    return hashlib.pbkdf2_hmac(
        "sha512",
        combined_block,
        salt,
        iterations,
        dklen=output_length_bytes,
    )


def derive_final_key_with_scrypt(
    combined_block: bytes,
    cost_n: int,
    cost_r: int,
    cost_p: int,
    output_length_bytes: int,
) -> bytes:
    salt = hashlib.sha512(b"VC2_SCRYPT_SALT" + combined_block).digest()

    return hashlib.scrypt(
        combined_block,
        salt=salt,
        n=cost_n,
        r=cost_r,
        p=cost_p,
        dklen=output_length_bytes,
    )


def derive_final_key_with_argon2id(
    combined_block: bytes,
    memory_kib: int,
    time_cost: int,
    parallelism: int,
    output_length_bytes: int,
) -> bytes:
    if not ARGON2_AVAILABLE:
        print(
            "ERROR: Argon2id requested but argon2-cffi is not installed.\n"
            "       Install with: pip install argon2-cffi",
            file=sys.stderr,
        )
        sys.exit(1)

    salt = hashlib.sha512(b"VC2_ARGON2ID_SALT" + combined_block).digest()

    return argon2_hash_secret_raw(
        secret=combined_block,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=output_length_bytes,
        type=Argon2Type.ID,
    )


# ---------------------------------------------------------------------------
# Clipboard
# ---------------------------------------------------------------------------

def running_under_wsl() -> bool:
    try:
        with open("/proc/version", "r") as version_file:
            return "microsoft" in version_file.read().lower()
    except Exception:
        return False


def copy_text_to_clipboard(text: str) -> bool:
    try:
        if running_under_wsl():
            process = subprocess.Popen(["clip.exe"], stdin=subprocess.PIPE)
            process.communicate(text.encode())
            return process.returncode == 0

        if sys.platform == "darwin":
            process = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            process.communicate(text.encode())
            return process.returncode == 0

        if sys.platform.startswith("win"):
            process = subprocess.Popen(["clip"], stdin=subprocess.PIPE)
            process.communicate(text.encode())
            return process.returncode == 0

        if shutil.which("xclip"):
            process = subprocess.Popen(
                ["xclip", "-selection", "clipboard"],
                stdin=subprocess.PIPE,
            )
            process.communicate(text.encode())
            return process.returncode == 0

        if shutil.which("xsel"):
            process = subprocess.Popen(
                ["xsel", "--clipboard", "--input"],
                stdin=subprocess.PIPE,
            )
            process.communicate(text.encode())
            return process.returncode == 0

        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Argument Parsing
# ---------------------------------------------------------------------------

def parse_command_line_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Two-passphrase deterministic key generator.",
    )

    # KDF selection
    parser.add_argument(
        "--kdf",
        choices=["pbkdf2", "scrypt", "argon2id"],
        default="pbkdf2",
        help="KDF to use: pbkdf2 (default), scrypt, or argon2id.",
    )

    # PBKDF2 options
    parser.add_argument(
        "--pbkdf2-iter",
        type=int,
        default=DEFAULT_PBKDF2_ITERATIONS,
        help=f"PBKDF2 iteration count (default {DEFAULT_PBKDF2_ITERATIONS}).",
    )

    # scrypt options
    parser.add_argument(
        "--scrypt-n",
        type=int,
        default=DEFAULT_SCRYPT_N,
        help=f"scrypt N parameter (CPU/memory cost, default {DEFAULT_SCRYPT_N}).",
    )
    parser.add_argument(
        "--scrypt-r",
        type=int,
        default=DEFAULT_SCRYPT_R,
        help=f"scrypt r parameter (block size, default {DEFAULT_SCRYPT_R}).",
    )
    parser.add_argument(
        "--scrypt-p",
        type=int,
        default=DEFAULT_SCRYPT_P,
        help=f"scrypt p parameter (parallelism, default {DEFAULT_SCRYPT_P}).",
    )

    # Argon2id options
    parser.add_argument(
        "--argon2-m",
        type=int,
        default=DEFAULT_ARGON2_MEMORY_KIB,
        help=f"Argon2id memory cost in KiB (default {DEFAULT_ARGON2_MEMORY_KIB}).",
    )
    parser.add_argument(
        "--argon2-t",
        type=int,
        default=DEFAULT_ARGON2_TIME_COST,
        help=f"Argon2id time cost / iterations (default {DEFAULT_ARGON2_TIME_COST}).",
    )
    parser.add_argument(
        "--argon2-p",
        type=int,
        default=DEFAULT_ARGON2_PARALLELISM,
        help=f"Argon2id parallelism (default {DEFAULT_ARGON2_PARALLELISM}).",
    )

    # Output mode
    parser.add_argument(
        "--output-mode",
        choices=["full", "veracrypt", "keyfile"],
        default="full",
        help="Output format: full (default), veracrypt, or keyfile.",
    )

    parser.add_argument(
        "--veracrypt",
        action="store_true",
        help="Shortcut for --output-mode veracrypt.",
    )

    parser.add_argument(
        "--keyfile",
        type=str,
        help="Path to write keyfile when using --output-mode keyfile.",
    )

    parser.add_argument(
        "--copy",
        action="store_true",
        help="Copy key to clipboard instead of printing it.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress extra output; print only the key or a success message.",
    )
    parser.add_argument(
        "--no-warnings",
        action="store_true",
        help="Suppress safety warnings.",
    )

    args = parser.parse_args()

    if args.veracrypt:
        args.output_mode = "veracrypt"

    return args


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_command_line_arguments()

    if args.output_mode == "keyfile" and not args.keyfile:
        print("ERROR: --output-mode keyfile requires --keyfile PATH.", file=sys.stderr)
        sys.exit(1)

    if args.output_mode == "keyfile" and args.copy:
        print("ERROR: --copy cannot be used with --output-mode keyfile.", file=sys.stderr)
        sys.exit(1)

    if not args.no_warnings and not args.quiet:
        print("WARNING: This tool derives sensitive key material.\n", file=sys.stderr)

    try:
        passphrase_one = prompt_for_passphrase("Passphrase #1")
        passphrase_two = prompt_for_passphrase("Passphrase #2")

        if passphrase_one == passphrase_two:
            print("WARNING: Passphrases #1 and #2 are identical.\n", file=sys.stderr)

        combined_block = build_two_passphrase_combined_block_sha3_blake2(
            passphrase_one,
            passphrase_two,
        )
        passphrase_one = None
        passphrase_two = None

        if args.kdf == "pbkdf2":
            key_bytes = derive_final_key_with_pbkdf2(
                combined_block,
                args.pbkdf2_iter,
                DEFAULT_KEY_LENGTH_BYTES,
            )
        elif args.kdf == "scrypt":
            key_bytes = derive_final_key_with_scrypt(
                combined_block,
                args.scrypt_n,
                args.scrypt_r,
                args.scrypt_p,
                DEFAULT_KEY_LENGTH_BYTES,
            )
        else:  # argon2id
            key_bytes = derive_final_key_with_argon2id(
                combined_block,
                args.argon2_m,
                args.argon2_t,
                args.argon2_p,
                DEFAULT_KEY_LENGTH_BYTES,
            )

        combined_block = None

        if args.output_mode == "keyfile":
            if os.path.exists(args.keyfile):
                print(
                    f"ERROR: Keyfile already exists: {args.keyfile}",
                    file=sys.stderr,
                )
                sys.exit(1)

            try:
                with open(args.keyfile, "wb") as keyfile_handle:
                    keyfile_handle.write(key_bytes)
            except OSError as error:
                print(f"ERROR: Failed to write keyfile: {error}", file=sys.stderr)
                sys.exit(1)

            if not args.quiet:
                print(f"Keyfile written: {args.keyfile}")
                print(f"Size: {len(key_bytes)} bytes", file=sys.stderr)
            return

        key_hex = key_bytes.hex()

        if args.output_mode == "veracrypt":
            key_hex = key_hex[:64]

        if args.copy:
            if not copy_text_to_clipboard(key_hex):
                print("ERROR: Failed to copy to clipboard.", file=sys.stderr)
                sys.exit(1)
            if not args.quiet:
                print("Key copied to clipboard.")
            return

        if args.quiet:
            print(key_hex)
        else:
            print("\n=== DERIVED KEY ===")
            print(key_hex)
            print("===================")

    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
