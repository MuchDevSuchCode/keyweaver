#!/usr/bin/env python3
"""
KeyWeaver — two-passphrase deterministic key generator.

OVERVIEW
========
Derives high-entropy key material from TWO independent passphrases.

  1. Prompt for Passphrase #1 (with confirmation)
  2. Prompt for Passphrase #2 (with confirmation)

  3. Build a 512-bit combined secret block from both passphrases:

       block_for_p1 = SHA3-256(p1) || BLAKE2b-256(p1, person="VC2_P1")
       block_for_p2 = SHA3-256(p2) || BLAKE2b-256(p2, person="VC2_P2")
       combined_block = XOR(block_for_p1, block_for_p2)

     Each passphrase is processed independently with two hash constructions.
     Personalization strings provide domain separation.

  4. Run KDF (PBKDF2-HMAC-SHA512, scrypt, or Argon2id) over the combined block:

         final_key = KDF(combined_block, deterministic_salt, ...)

  5. Output key material in hex or as a binary keyfile.

DETERMINISM CONTRACT
====================
The defaults below are part of the determinism contract. Changing any of
the following bytes-for-bytes will produce different output for the same
passphrase pair:

  - Personalization strings (VC2_P1, VC2_P2)
  - Salt label strings (VC2_PBKDF2_SALT, VC2_SCRYPT_SALT, VC2_ARGON2ID_SALT)
  - Default KDF parameters (iterations, N/r/p, memory/time/parallelism)
  - Default key length (128 bytes)
  - VeraCrypt truncation (first 64 hex chars)

These values MUST NOT be changed without a major version bump.

OUTPUT MODES
============
  --output-mode full       full 128-byte key (256 hex chars, default)
  --output-mode veracrypt  first 32 bytes (64 hex chars)
  --output-mode keyfile    write raw bytes to file (mode 0600 on Unix)

KDF OPTIONS
===========
  PBKDF2-HMAC-SHA512:
    --kdf pbkdf2 (default)
    --pbkdf2-iter N            (default 600000)

  scrypt:
    --kdf scrypt
    --scrypt-n N               (CPU/memory cost, default 16384)
    --scrypt-r R               (block size, default 8)
    --scrypt-p P               (parallelism, default 1)

  Argon2id:
    --kdf argon2id             (requires argon2-cffi)
    --argon2-m MEM_KIB         (memory cost in KiB, default 65536 = 64 MiB)
    --argon2-t T               (time cost / iterations, default 3)
    --argon2-p P               (parallelism, default 1)

SECURITY MODEL
==============
  - Anyone who learns BOTH passphrases (and the parameters) can derive the
    key. Anyone who learns the final key, or a keyfile, can decrypt.
  - The salt is deterministic by design — security rests on passphrase
    entropy and KDF cost. Use long, high-entropy, non-reused passphrases.
  - Memory wiping is best-effort; Python cannot guarantee that secrets
    are removed from RAM. Consider OS-level protections (encrypted swap,
    locked memory) for high-value workflows.
"""

import argparse
import getpass
import hashlib
import math
import os
import shutil
import subprocess
import sys
import time

try:
    from argon2.low_level import Type as Argon2Type, hash_secret_raw as argon2_hash_secret_raw
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


# ---------------------------------------------------------------------------
# Determinism contract — DO NOT change these without a major version bump.
# ---------------------------------------------------------------------------

DEFAULT_KEY_LENGTH_BYTES = 128
DEFAULT_PBKDF2_ITERATIONS = 600_000

DEFAULT_SCRYPT_N = 2 ** 14
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1

DEFAULT_ARGON2_MEMORY_KIB = 64 * 1024
DEFAULT_ARGON2_TIME_COST = 3
DEFAULT_ARGON2_PARALLELISM = 1

PERSON_P1 = b"VC2_P1"
PERSON_P2 = b"VC2_P2"
SALT_LABEL_PBKDF2 = b"VC2_PBKDF2_SALT"
SALT_LABEL_SCRYPT = b"VC2_SCRYPT_SALT"
SALT_LABEL_ARGON2 = b"VC2_ARGON2ID_SALT"

FINGERPRINT_PERSON = b"VC2_FP__"
FINGERPRINT_BYTES = 8

DEFAULT_COPY_TIMEOUT_SECONDS = 30
DEFAULT_MIN_ENTROPY_BITS = 0  # advisory only by default


# ---------------------------------------------------------------------------
# Memory hygiene helpers
# ---------------------------------------------------------------------------

def secure_zero(buf) -> None:
    """Best-effort wipe of a bytearray. No-op for immutable bytes/str."""
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


# ---------------------------------------------------------------------------
# Passphrase strength estimation
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
        first = getpass.getpass(f"Enter {label}: ")
        second = getpass.getpass(f"Re-enter {label}: ")

        if first != second:
            print("Passphrases do not match.\n", file=sys.stderr)
            continue
        if not first:
            print("Passphrase cannot be empty.\n", file=sys.stderr)
            continue

        warn_if_passphrase_weak(first, label)
        return first


# ---------------------------------------------------------------------------
# Two-passphrase combiner
# ---------------------------------------------------------------------------

def build_combined_block(passphrase_one: str, passphrase_two: str) -> bytearray:
    """
    Returns a 512-bit (64-byte) bytearray:

        XOR(
            SHA3-256(p1) || BLAKE2b-256(p1, person=VC2_P1),
            SHA3-256(p2) || BLAKE2b-256(p2, person=VC2_P2)
        )

    A bytearray is returned so callers can wipe it with secure_zero().
    """
    def block_for(passphrase: str, personalization: bytes) -> bytes:
        passphrase_bytes = passphrase.encode("utf-8")
        sha3_part = hashlib.sha3_256(passphrase_bytes).digest()
        blake2_part = hashlib.blake2b(
            passphrase_bytes,
            digest_size=32,
            person=personalization,
        ).digest()
        return sha3_part + blake2_part

    block_one = block_for(passphrase_one, PERSON_P1)
    block_two = block_for(passphrase_two, PERSON_P2)

    combined = bytearray(len(block_one))
    for i in range(len(block_one)):
        combined[i] = block_one[i] ^ block_two[i]
    return combined


# ---------------------------------------------------------------------------
# KDF layers
# ---------------------------------------------------------------------------

def derive_with_pbkdf2(combined_block: bytes, iterations: int, output_length: int) -> bytes:
    salt = hashlib.sha512(SALT_LABEL_PBKDF2 + bytes(combined_block)).digest()
    return hashlib.pbkdf2_hmac(
        "sha512",
        bytes(combined_block),
        salt,
        iterations,
        dklen=output_length,
    )


def derive_with_scrypt(
    combined_block: bytes,
    cost_n: int,
    cost_r: int,
    cost_p: int,
    output_length: int,
) -> bytes:
    salt = hashlib.sha512(SALT_LABEL_SCRYPT + bytes(combined_block)).digest()
    return hashlib.scrypt(
        bytes(combined_block),
        salt=salt,
        n=cost_n,
        r=cost_r,
        p=cost_p,
        dklen=output_length,
    )


def derive_with_argon2id(
    combined_block: bytes,
    memory_kib: int,
    time_cost: int,
    parallelism: int,
    output_length: int,
) -> bytes:
    if not ARGON2_AVAILABLE:
        raise RuntimeError(
            "Argon2id requested but argon2-cffi is not installed.\n"
            "Install with: pip install argon2-cffi"
        )

    salt = hashlib.sha512(SALT_LABEL_ARGON2 + bytes(combined_block)).digest()
    return argon2_hash_secret_raw(
        secret=bytes(combined_block),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=output_length,
        type=Argon2Type.ID,
    )


def derive_key(
    passphrase_one: str,
    passphrase_two: str,
    kdf: str,
    *,
    output_length: int = DEFAULT_KEY_LENGTH_BYTES,
    pbkdf2_iter: int = DEFAULT_PBKDF2_ITERATIONS,
    scrypt_n: int = DEFAULT_SCRYPT_N,
    scrypt_r: int = DEFAULT_SCRYPT_R,
    scrypt_p: int = DEFAULT_SCRYPT_P,
    argon2_m: int = DEFAULT_ARGON2_MEMORY_KIB,
    argon2_t: int = DEFAULT_ARGON2_TIME_COST,
    argon2_p: int = DEFAULT_ARGON2_PARALLELISM,
) -> bytes:
    """High-level convenience entry point. Used by the GUI."""
    combined = build_combined_block(passphrase_one, passphrase_two)
    try:
        if kdf == "pbkdf2":
            return derive_with_pbkdf2(combined, pbkdf2_iter, output_length)
        if kdf == "scrypt":
            return derive_with_scrypt(combined, scrypt_n, scrypt_r, scrypt_p, output_length)
        if kdf == "argon2id":
            return derive_with_argon2id(combined, argon2_m, argon2_t, argon2_p, output_length)
        raise ValueError(f"Unknown KDF: {kdf!r}")
    finally:
        secure_zero(combined)


def key_fingerprint(key_bytes: bytes) -> str:
    """Short non-reversible tag — lets a user verify they typed the right pair
    without revealing key material."""
    return hashlib.blake2b(
        key_bytes,
        digest_size=FINGERPRINT_BYTES,
        person=FINGERPRINT_PERSON,
    ).hexdigest()


# ---------------------------------------------------------------------------
# Keyfile output (atomic, restrictive permissions)
# ---------------------------------------------------------------------------

def write_keyfile_secure(path: str, data: bytes) -> None:
    """Open with O_EXCL so existing files are not overwritten; mode 0600 on Unix."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


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
            cmd = ["clip.exe"]
        elif sys.platform == "darwin":
            cmd = ["pbcopy"]
        elif sys.platform.startswith("win"):
            cmd = ["clip"]
        elif shutil.which("wl-copy"):
            cmd = ["wl-copy"]
        elif shutil.which("xclip"):
            cmd = ["xclip", "-selection", "clipboard"]
        elif shutil.which("xsel"):
            cmd = ["xsel", "--clipboard", "--input"]
        else:
            return False

        process = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        process.communicate(text.encode())
        return process.returncode == 0
    except Exception:
        return False


def clear_clipboard() -> None:
    """Overwrite clipboard with whitespace. Cannot truly 'clear' on every OS;
    overwriting with non-secret content is the standard mitigation."""
    copy_text_to_clipboard(" " * 64)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_command_line_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="KeyWeaver — two-passphrase deterministic key generator.",
    )

    parser.add_argument(
        "--kdf",
        choices=["pbkdf2", "scrypt", "argon2id"],
        default=None,
        help="KDF: pbkdf2 (default), scrypt, or argon2id. "
             "Argon2id is the modern best practice and is recommended for new keys.",
    )

    parser.add_argument(
        "--pbkdf2-iter",
        type=int,
        default=DEFAULT_PBKDF2_ITERATIONS,
        help=f"PBKDF2 iteration count (default {DEFAULT_PBKDF2_ITERATIONS}).",
    )

    parser.add_argument(
        "--scrypt-n",
        type=int,
        default=DEFAULT_SCRYPT_N,
        help=f"scrypt N (CPU/memory cost, default {DEFAULT_SCRYPT_N}).",
    )
    parser.add_argument(
        "--scrypt-r",
        type=int,
        default=DEFAULT_SCRYPT_R,
        help=f"scrypt r (block size, default {DEFAULT_SCRYPT_R}).",
    )
    parser.add_argument(
        "--scrypt-p",
        type=int,
        default=DEFAULT_SCRYPT_P,
        help=f"scrypt p (parallelism, default {DEFAULT_SCRYPT_P}).",
    )

    parser.add_argument(
        "--argon2-m",
        type=int,
        default=DEFAULT_ARGON2_MEMORY_KIB,
        help=f"Argon2id memory in KiB (default {DEFAULT_ARGON2_MEMORY_KIB}).",
    )
    parser.add_argument(
        "--argon2-t",
        type=int,
        default=DEFAULT_ARGON2_TIME_COST,
        help=f"Argon2id time cost (default {DEFAULT_ARGON2_TIME_COST}).",
    )
    parser.add_argument(
        "--argon2-p",
        type=int,
        default=DEFAULT_ARGON2_PARALLELISM,
        help=f"Argon2id parallelism (default {DEFAULT_ARGON2_PARALLELISM}).",
    )

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
        "--copy-timeout",
        type=int,
        default=DEFAULT_COPY_TIMEOUT_SECONDS,
        help=(
            f"Seconds to keep key on clipboard before overwriting (default "
            f"{DEFAULT_COPY_TIMEOUT_SECONDS}). 0 = never auto-clear."
        ),
    )
    parser.add_argument(
        "--fingerprint",
        action="store_true",
        help="Also print a short non-reversible fingerprint of the derived key.",
    )
    parser.add_argument(
        "--min-entropy",
        type=float,
        default=DEFAULT_MIN_ENTROPY_BITS,
        help="Refuse to proceed if either passphrase has fewer estimated bits than this (use --force to override).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Bypass --min-entropy refusal.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress extra output; print only the key or success message.",
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

    kdf_was_unspecified = args.kdf is None
    if kdf_was_unspecified:
        args.kdf = "pbkdf2"

    if (
        kdf_was_unspecified
        and not args.no_warnings
        and not args.quiet
    ):
        print(
            "NOTE: Using PBKDF2 (default). Argon2id is the modern best practice\n"
            "      for new keys. Re-run with --kdf argon2id to use it.\n"
            "      (Suppress this notice with --no-warnings.)\n",
            file=sys.stderr,
        )

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

        if args.min_entropy > 0:
            bits_one = estimate_passphrase_entropy_bits(passphrase_one)
            bits_two = estimate_passphrase_entropy_bits(passphrase_two)
            weakest = min(bits_one, bits_two)
            if weakest < args.min_entropy and not args.force:
                print(
                    f"ERROR: Weakest passphrase is ~{weakest:.1f} bits, "
                    f"below the --min-entropy threshold of {args.min_entropy:.1f}.\n"
                    f"       Re-run with stronger passphrases, or pass --force to override.",
                    file=sys.stderr,
                )
                sys.exit(1)

        try:
            key_bytes = derive_key(
                passphrase_one,
                passphrase_two,
                args.kdf,
                output_length=DEFAULT_KEY_LENGTH_BYTES,
                pbkdf2_iter=args.pbkdf2_iter,
                scrypt_n=args.scrypt_n,
                scrypt_r=args.scrypt_r,
                scrypt_p=args.scrypt_p,
                argon2_m=args.argon2_m,
                argon2_t=args.argon2_t,
                argon2_p=args.argon2_p,
            )
        except RuntimeError as error:
            print(f"ERROR: {error}", file=sys.stderr)
            sys.exit(1)
        finally:
            passphrase_one = None
            passphrase_two = None

        if args.output_mode == "keyfile":
            try:
                write_keyfile_secure(args.keyfile, key_bytes)
            except FileExistsError:
                print(f"ERROR: Keyfile already exists: {args.keyfile}", file=sys.stderr)
                sys.exit(1)
            except OSError as error:
                print(f"ERROR: Failed to write keyfile: {error}", file=sys.stderr)
                sys.exit(1)

            if not args.quiet:
                print(f"Keyfile written: {args.keyfile}")
                print(f"Size: {len(key_bytes)} bytes", file=sys.stderr)
                if args.fingerprint:
                    print(f"Fingerprint: {key_fingerprint(key_bytes)}", file=sys.stderr)
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
                if args.fingerprint:
                    print(f"Fingerprint: {key_fingerprint(key_bytes)}")

            if args.copy_timeout > 0:
                if not args.quiet:
                    print(
                        f"Clipboard will be overwritten in {args.copy_timeout}s. "
                        f"Press Ctrl+C to clear immediately."
                    )
                try:
                    time.sleep(args.copy_timeout)
                except KeyboardInterrupt:
                    pass
                clear_clipboard()
                if not args.quiet:
                    print("Clipboard overwritten.")
            return

        if args.quiet:
            print(key_hex)
        else:
            print("\n=== DERIVED KEY ===")
            print(key_hex)
            print("===================")
            if args.fingerprint:
                print(f"Fingerprint: {key_fingerprint(key_bytes)}")

    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
