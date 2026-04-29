#!/usr/bin/env python3
"""
KeyWeaver — Tkinter GUI.

Stdlib-only. Imports the crypto from keyweaver.py so there is exactly one
implementation of the derivation logic.

Run:  python keyweaver_gui.py
"""

import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import keyweaver as kw


CLIPBOARD_TIMEOUT_SECONDS = 30


class KeyWeaverGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("KeyWeaver")
        self.root.minsize(640, 720)

        self._derived_key_bytes: bytes | None = None
        self._clipboard_timer_id: str | None = None

        self.kdf_var = tk.StringVar(value="pbkdf2")
        self.output_mode_var = tk.StringVar(value="full")
        self.show_p1 = tk.BooleanVar(value=False)
        self.show_p2 = tk.BooleanVar(value=False)

        self.pbkdf2_iter = tk.IntVar(value=kw.DEFAULT_PBKDF2_ITERATIONS)
        self.scrypt_n = tk.IntVar(value=kw.DEFAULT_SCRYPT_N)
        self.scrypt_r = tk.IntVar(value=kw.DEFAULT_SCRYPT_R)
        self.scrypt_p = tk.IntVar(value=kw.DEFAULT_SCRYPT_P)
        self.argon2_m = tk.IntVar(value=kw.DEFAULT_ARGON2_MEMORY_KIB)
        self.argon2_t = tk.IntVar(value=kw.DEFAULT_ARGON2_TIME_COST)
        self.argon2_p = tk.IntVar(value=kw.DEFAULT_ARGON2_PARALLELISM)

        self.keyfile_path = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Ready.")

        self._build_layout()
        self._update_kdf_panel()
        self._update_output_panel()

    # -- Layout -----------------------------------------------------------

    def _build_layout(self) -> None:
        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)

        header = ttk.Label(
            outer,
            text="KeyWeaver",
            font=("Segoe UI", 18, "bold"),
        )
        subhead = ttk.Label(
            outer,
            text="Two-passphrase deterministic key generator",
            font=("Segoe UI", 10),
            foreground="#666",
        )
        header.grid(row=0, column=0, sticky="w")
        subhead.grid(row=1, column=0, sticky="w", pady=(0, 8))

        self._build_passphrase_section(outer, row=2, label="Passphrase #1",
                                       index=1, show_var=self.show_p1)
        self._build_passphrase_section(outer, row=3, label="Passphrase #2",
                                       index=2, show_var=self.show_p2)

        self._build_kdf_section(outer, row=4)
        self._build_output_section(outer, row=5)
        self._build_action_section(outer, row=6)
        self._build_result_section(outer, row=7)

        status = ttk.Label(outer, textvariable=self.status_var, foreground="#444")
        status.grid(row=8, column=0, sticky="w", pady=(8, 0))

        outer.rowconfigure(7, weight=1)

    def _build_passphrase_section(self, parent, row, label, index, show_var):
        frame = ttk.LabelFrame(parent, text=label, padding=8)
        frame.grid(row=row, column=0, sticky="ew", pady=4)
        frame.columnconfigure(1, weight=1)

        ttk.Label(frame, text="Enter:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        entry1 = ttk.Entry(frame, show="*", width=44)
        entry1.grid(row=0, column=1, sticky="ew")

        ttk.Label(frame, text="Confirm:").grid(row=1, column=0, sticky="w", padx=(0, 6), pady=(4, 0))
        entry2 = ttk.Entry(frame, show="*", width=44)
        entry2.grid(row=1, column=1, sticky="ew", pady=(4, 0))

        show_check = ttk.Checkbutton(
            frame, text="Show", variable=show_var,
            command=lambda: self._toggle_show(entry1, entry2, show_var),
        )
        show_check.grid(row=0, column=2, rowspan=2, padx=(8, 0))

        meter = ttk.Progressbar(frame, mode="determinate", maximum=160, length=240)
        meter.grid(row=2, column=1, sticky="ew", pady=(8, 0))

        meter_label = ttk.Label(frame, text="Strength: 0 bits", foreground="#666")
        meter_label.grid(row=2, column=2, sticky="w", padx=(8, 0), pady=(8, 0))

        entry1.bind("<KeyRelease>",
                    lambda _e: self._update_strength(entry1, meter, meter_label))

        if index == 1:
            self.entry_p1_a, self.entry_p1_b = entry1, entry2
        else:
            self.entry_p2_a, self.entry_p2_b = entry1, entry2

    def _build_kdf_section(self, parent, row):
        frame = ttk.LabelFrame(parent, text="Key Derivation Function", padding=8)
        frame.grid(row=row, column=0, sticky="ew", pady=4)
        frame.columnconfigure(0, weight=1)

        radios = ttk.Frame(frame)
        radios.grid(row=0, column=0, sticky="w")

        for value, label in (("pbkdf2", "PBKDF2-SHA512"),
                             ("scrypt", "scrypt"),
                             ("argon2id", "Argon2id")):
            rb = ttk.Radiobutton(radios, text=label, variable=self.kdf_var,
                                 value=value, command=self._update_kdf_panel)
            rb.pack(side="left", padx=(0, 12))
            if value == "argon2id" and not kw.ARGON2_AVAILABLE:
                rb.state(["disabled"])

        self.kdf_params_frame = ttk.Frame(frame)
        self.kdf_params_frame.grid(row=1, column=0, sticky="ew", pady=(8, 0))

    def _update_kdf_panel(self):
        for child in self.kdf_params_frame.winfo_children():
            child.destroy()

        kdf = self.kdf_var.get()
        f = self.kdf_params_frame
        if kdf == "pbkdf2":
            ttk.Label(f, text="Iterations:").grid(row=0, column=0, sticky="w")
            ttk.Spinbox(f, from_=100_000, to=10_000_000, increment=100_000,
                        textvariable=self.pbkdf2_iter, width=12).grid(row=0, column=1, padx=6)
        elif kdf == "scrypt":
            ttk.Label(f, text="N:").grid(row=0, column=0, sticky="w")
            ttk.Spinbox(f, from_=1024, to=2 ** 22, increment=1024,
                        textvariable=self.scrypt_n, width=10).grid(row=0, column=1, padx=6)
            ttk.Label(f, text="r:").grid(row=0, column=2, sticky="w")
            ttk.Spinbox(f, from_=1, to=32, textvariable=self.scrypt_r, width=6).grid(row=0, column=3, padx=6)
            ttk.Label(f, text="p:").grid(row=0, column=4, sticky="w")
            ttk.Spinbox(f, from_=1, to=16, textvariable=self.scrypt_p, width=6).grid(row=0, column=5, padx=6)
        else:  # argon2id
            if not kw.ARGON2_AVAILABLE:
                ttk.Label(f, text="argon2-cffi not installed.",
                          foreground="#a00").grid(row=0, column=0, sticky="w")
                return
            ttk.Label(f, text="Memory (KiB):").grid(row=0, column=0, sticky="w")
            ttk.Spinbox(f, from_=8192, to=4 * 1024 * 1024, increment=8192,
                        textvariable=self.argon2_m, width=12).grid(row=0, column=1, padx=6)
            ttk.Label(f, text="Time:").grid(row=0, column=2, sticky="w")
            ttk.Spinbox(f, from_=1, to=20, textvariable=self.argon2_t, width=6).grid(row=0, column=3, padx=6)
            ttk.Label(f, text="Parallelism:").grid(row=0, column=4, sticky="w")
            ttk.Spinbox(f, from_=1, to=16, textvariable=self.argon2_p, width=6).grid(row=0, column=5, padx=6)

    def _build_output_section(self, parent, row):
        frame = ttk.LabelFrame(parent, text="Output", padding=8)
        frame.grid(row=row, column=0, sticky="ew", pady=4)
        frame.columnconfigure(1, weight=1)

        radios = ttk.Frame(frame)
        radios.grid(row=0, column=0, columnspan=3, sticky="w")
        for value, label in (("full", "Full 128-byte hex"),
                             ("veracrypt", "VeraCrypt 32-byte hex"),
                             ("keyfile", "Binary keyfile")):
            ttk.Radiobutton(radios, text=label, variable=self.output_mode_var,
                            value=value, command=self._update_output_panel
                            ).pack(side="left", padx=(0, 12))

        self.keyfile_row = ttk.Frame(frame)
        self.keyfile_row.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        self.keyfile_row.columnconfigure(1, weight=1)
        ttk.Label(self.keyfile_row, text="Keyfile path:").grid(row=0, column=0, sticky="w")
        ttk.Entry(self.keyfile_row, textvariable=self.keyfile_path).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(self.keyfile_row, text="Browse…", command=self._browse_keyfile
                   ).grid(row=0, column=2)

    def _update_output_panel(self):
        if self.output_mode_var.get() == "keyfile":
            for child in self.keyfile_row.winfo_children():
                child.grid()
        else:
            for child in self.keyfile_row.winfo_children():
                child.grid_remove()

    def _build_action_section(self, parent, row):
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=0, sticky="ew", pady=8)
        self.generate_btn = ttk.Button(frame, text="Generate Key", command=self._on_generate)
        self.generate_btn.pack(side="left")
        ttk.Button(frame, text="Clear All", command=self._clear_all).pack(side="left", padx=8)

    def _build_result_section(self, parent, row):
        frame = ttk.LabelFrame(parent, text="Result", padding=8)
        frame.grid(row=row, column=0, sticky="nsew", pady=4)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        self.result_text = tk.Text(frame, height=6, wrap="word", font=("Consolas", 10),
                                   state="disabled", bg="#fafafa")
        self.result_text.grid(row=0, column=0, sticky="nsew")

        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.result_text.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.result_text.configure(yscrollcommand=scroll.set)

        self.fingerprint_var = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.fingerprint_var, foreground="#444",
                  font=("Consolas", 9)).grid(row=1, column=0, sticky="w", pady=(6, 0))

        actions = ttk.Frame(frame)
        actions.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        self.copy_btn = ttk.Button(actions, text=f"Copy (auto-clear {CLIPBOARD_TIMEOUT_SECONDS}s)",
                                   command=self._copy_with_timeout, state="disabled")
        self.copy_btn.pack(side="left")
        self.save_btn = ttk.Button(actions, text="Save Keyfile…", command=self._save_keyfile_dialog,
                                   state="disabled")
        self.save_btn.pack(side="left", padx=8)
        self.wipe_btn = ttk.Button(actions, text="Wipe Result", command=self._wipe_result,
                                   state="disabled")
        self.wipe_btn.pack(side="left")

    # -- Behaviour --------------------------------------------------------

    def _toggle_show(self, e1, e2, var):
        char = "" if var.get() else "*"
        e1.config(show=char)
        e2.config(show=char)

    def _update_strength(self, entry, meter, label):
        bits = kw.estimate_passphrase_entropy_bits(entry.get())
        meter["value"] = min(bits, 160)
        label.config(text=f"Strength: {bits:.0f} bits")

    def _browse_keyfile(self):
        path = filedialog.asksaveasfilename(
            title="Save keyfile as",
            defaultextension=".key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")],
        )
        if path:
            self.keyfile_path.set(path)

    def _validate_inputs(self) -> tuple[str, str] | None:
        p1a, p1b = self.entry_p1_a.get(), self.entry_p1_b.get()
        p2a, p2b = self.entry_p2_a.get(), self.entry_p2_b.get()

        if not p1a or not p2a:
            messagebox.showerror("Missing input", "Both passphrases are required.")
            return None
        if p1a != p1b:
            messagebox.showerror("Mismatch", "Passphrase #1 confirmation does not match.")
            return None
        if p2a != p2b:
            messagebox.showerror("Mismatch", "Passphrase #2 confirmation does not match.")
            return None
        if p1a == p2a:
            if not messagebox.askyesno(
                "Identical passphrases",
                "Both passphrases are identical. This significantly weakens the result.\n\nContinue anyway?",
            ):
                return None
        return p1a, p2a

    def _on_generate(self):
        validated = self._validate_inputs()
        if validated is None:
            return
        p1, p2 = validated

        if self.output_mode_var.get() == "keyfile" and not self.keyfile_path.get():
            messagebox.showerror("Missing path", "Choose a path for the keyfile.")
            return

        self.generate_btn.state(["disabled"])
        self.status_var.set("Deriving key… (this may take several seconds)")
        self.root.update_idletasks()

        thread = threading.Thread(
            target=self._derive_in_background,
            args=(p1, p2),
            daemon=True,
        )
        thread.start()

    def _derive_in_background(self, p1: str, p2: str):
        kdf = self.kdf_var.get()
        try:
            key_bytes = kw.derive_key(
                p1, p2, kdf,
                pbkdf2_iter=self.pbkdf2_iter.get(),
                scrypt_n=self.scrypt_n.get(),
                scrypt_r=self.scrypt_r.get(),
                scrypt_p=self.scrypt_p.get(),
                argon2_m=self.argon2_m.get(),
                argon2_t=self.argon2_t.get(),
                argon2_p=self.argon2_p.get(),
            )
        except Exception as error:  # surface to UI thread
            self.root.after(0, lambda: self._on_derive_failed(str(error)))
            return
        self.root.after(0, lambda: self._on_derive_succeeded(key_bytes))

    def _on_derive_failed(self, message: str):
        self.generate_btn.state(["!disabled"])
        self.status_var.set("Derivation failed.")
        messagebox.showerror("Derivation failed", message)

    def _on_derive_succeeded(self, key_bytes: bytes):
        self._derived_key_bytes = key_bytes
        mode = self.output_mode_var.get()

        if mode == "keyfile":
            try:
                kw.write_keyfile_secure(self.keyfile_path.get(), key_bytes)
            except FileExistsError:
                self._on_derive_failed(f"Keyfile already exists: {self.keyfile_path.get()}")
                return
            except OSError as error:
                self._on_derive_failed(f"Failed to write keyfile: {error}")
                return

            self._set_result_text(
                f"Keyfile written: {self.keyfile_path.get()}\n"
                f"Size: {len(key_bytes)} bytes"
            )
            self.fingerprint_var.set(f"Fingerprint: {kw.key_fingerprint(key_bytes)}")
            self.copy_btn.state(["disabled"])
            self.save_btn.state(["disabled"])
            self.wipe_btn.state(["!disabled"])
        else:
            key_hex = key_bytes.hex()
            if mode == "veracrypt":
                key_hex = key_hex[:64]
            self._set_result_text(key_hex)
            self.fingerprint_var.set(f"Fingerprint: {kw.key_fingerprint(key_bytes)}")
            self.copy_btn.state(["!disabled"])
            self.save_btn.state(["!disabled"])
            self.wipe_btn.state(["!disabled"])

        self.generate_btn.state(["!disabled"])
        self.status_var.set("Derivation complete.")

    def _set_result_text(self, text: str):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.insert("1.0", text)
        self.result_text.config(state="disabled")

    def _current_result_text(self) -> str:
        return self.result_text.get("1.0", "end-1c")

    def _copy_with_timeout(self):
        text = self._current_result_text()
        if not text:
            return
        if not kw.copy_text_to_clipboard(text):
            messagebox.showerror("Clipboard error", "Could not access the system clipboard.")
            return
        self.status_var.set(f"Copied. Auto-clear in {CLIPBOARD_TIMEOUT_SECONDS}s.")
        if self._clipboard_timer_id is not None:
            self.root.after_cancel(self._clipboard_timer_id)
        self._clipboard_timer_id = self.root.after(
            CLIPBOARD_TIMEOUT_SECONDS * 1000, self._clear_clipboard_now
        )

    def _clear_clipboard_now(self):
        kw.clear_clipboard()
        self._clipboard_timer_id = None
        self.status_var.set("Clipboard overwritten.")

    def _save_keyfile_dialog(self):
        if self._derived_key_bytes is None:
            return
        path = filedialog.asksaveasfilename(
            title="Save keyfile as",
            defaultextension=".key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            kw.write_keyfile_secure(path, self._derived_key_bytes)
        except FileExistsError:
            messagebox.showerror("Exists", "Keyfile already exists. Choose another path.")
            return
        except OSError as error:
            messagebox.showerror("Write failed", str(error))
            return
        self.status_var.set(f"Keyfile written: {os.path.basename(path)}")

    def _wipe_result(self):
        self._derived_key_bytes = None
        self._set_result_text("")
        self.fingerprint_var.set("")
        self.copy_btn.state(["disabled"])
        self.save_btn.state(["disabled"])
        self.wipe_btn.state(["disabled"])
        self.status_var.set("Result wiped.")

    def _clear_all(self):
        for entry in (self.entry_p1_a, self.entry_p1_b,
                      self.entry_p2_a, self.entry_p2_b):
            entry.delete(0, "end")
        self._wipe_result()
        self.status_var.set("Cleared.")


def main() -> None:
    root = tk.Tk()
    try:
        # Modern look on Windows / nicer defaults elsewhere.
        ttk.Style().theme_use("vista" if "vista" in ttk.Style().theme_names() else "clam")
    except tk.TclError:
        pass
    KeyWeaverGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
