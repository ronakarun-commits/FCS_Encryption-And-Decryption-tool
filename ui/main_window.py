"""Main Tkinter window for the encryption tool."""

from __future__ import annotations

import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

from crypto_utils import ARGON2_KDF_ID, KDF_ID, decrypt_file, encrypt_file, is_argon2_available, parse_sfet_header
from file_utils import calculate_sha256, log_activity, validate_password_strength
from ui.helpers import get_selected_file_size


class SecureFileApp(tk.Tk):
    """Desktop GUI for local file encryption and decryption."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Secure File Encryption Tool")
        self.geometry("700x470")
        self.minsize(560, 420)

        self.input_path_var = tk.StringVar()
        self.output_dir_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.sha_var = tk.StringVar(value="SHA-256: not calculated")
        self.file_size_var = tk.StringVar(value="File size: not selected")
        self.current_task = "idle"
        self.kdf_choice_var = tk.StringVar(value="PBKDF2")

        self._build_ui()
        self._set_busy(False)

    def _build_ui(self) -> None:
        main = tk.Frame(self, padx=20, pady=20)
        main.pack(fill="both", expand=True)

        title = tk.Label(main, text="SECURE FILE ENCRYPTION TOOL", font=("Arial", 16, "bold"))
        title.pack(pady=(0, 18))

        tk.Label(main, text="Select File:", anchor="w").pack(fill="x")
        row1 = tk.Frame(main)
        row1.pack(fill="x", pady=(4, 10))
        self.input_entry = tk.Entry(row1, textvariable=self.input_path_var)
        self.input_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        tk.Button(row1, text="Browse", command=self.browse_input_file, width=12).pack(side="right")

        self.file_info_label = tk.Label(main, textvariable=self.file_size_var, anchor="w", fg="#555")
        self.file_info_label.pack(anchor="w", pady=(0, 10))

        tk.Label(main, text="Password:", anchor="w").pack(fill="x")
        row2 = tk.Frame(main)
        row2.pack(fill="x", pady=(4, 10))
        self.password_entry = tk.Entry(row2, textvariable=self.password_var, show="*", width=30)
        self.password_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        tk.Button(row2, text="Show", command=self.toggle_password_visibility, width=12).pack(side="right")

        tk.Label(main, text="Key Derivation:", anchor="w").pack(fill="x")
        row_kdf = tk.Frame(main)
        row_kdf.pack(fill="x", pady=(4, 10))
        options = ["PBKDF2"]
        if is_argon2_available():
            options.append("Argon2id")
        self.kdf_menu = tk.OptionMenu(row_kdf, self.kdf_choice_var, *options)
        self.kdf_menu.pack(side="left")
        tk.Label(row_kdf, text="(PBKDF2 is simple and compatible; Argon2id is stronger)", fg="#666").pack(side="left", padx=(12, 0))

        tk.Label(main, text="Output Location:", anchor="w").pack(fill="x")
        row3 = tk.Frame(main)
        row3.pack(fill="x", pady=(4, 12))
        self.output_entry = tk.Entry(row3, textvariable=self.output_dir_var)
        self.output_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        tk.Button(row3, text="Browse", command=self.browse_output_dir, width=12).pack(side="right")

        buttons = tk.Frame(main)
        buttons.pack(fill="x", pady=(8, 10))
        tk.Button(buttons, text="Encrypt File", command=self.encrypt_file, width=18, bg="#d9f2d9").pack(side="left", padx=(0, 10))
        tk.Button(buttons, text="Decrypt File", command=self.decrypt_file, width=18, bg="#d9ebff").pack(side="left", padx=(0, 10))
        tk.Button(buttons, text="Calculate SHA-256", command=self.calculate_sha_button, width=20).pack(side="left")

        self.strength_label = tk.Label(main, text="Password strength: not checked", fg="gray")
        self.strength_label.pack(anchor="w", pady=(0, 8))
        self.password_entry.bind("<KeyRelease>", self.update_strength_indicator)

        self.sha_display = tk.Label(main, textvariable=self.sha_var, justify="left", wraplength=640, fg="#333")
        self.sha_display.pack(anchor="w", pady=(4, 8))

        tk.Label(main, text="Status:", anchor="w").pack(fill="x")
        status = tk.Label(main, textvariable=self.status_var, anchor="w", fg="#333", bd=1, relief="solid", padx=8, pady=6)
        status.pack(fill="x")

    def _set_busy(self, busy: bool) -> None:
        self.current_task = "busy" if busy else "idle"
        for widget in (self.input_entry, self.password_entry, self.output_entry, self.kdf_menu):
            if widget is not None:
                widget.configure(state="disabled" if busy else "normal")
        for btn in self.winfo_children():
            if isinstance(btn, tk.Frame):
                for child in btn.winfo_children():
                    if isinstance(child, tk.Button):
                        child.configure(state="disabled" if busy else "normal")

    def _update_file_size(self) -> None:
        self.file_size_var.set(get_selected_file_size(self.input_path_var.get().strip()))

    def browse_input_file(self) -> None:
        path = filedialog.askopenfilename(title="Select a file to encrypt or decrypt")
        if path:
            self.input_path_var.set(path)
            self._update_file_size()
            if not self.output_dir_var.get():
                self.output_dir_var.set(str(Path(path).parent))

    def browse_output_dir(self) -> None:
        folder = filedialog.askdirectory(title="Select output folder")
        if folder:
            self.output_dir_var.set(folder)

    def toggle_password_visibility(self) -> None:
        current = self.password_entry.cget("show")
        self.password_entry.configure(show="" if current == "*" else "*")

    def update_strength_indicator(self, event=None) -> None:
        password = self.password_var.get()
        if not password:
            self.strength_label.config(text="Password strength: not checked", fg="gray")
            return
        details = validate_password_strength(password)
        color = {"Weak": "red", "Medium": "orange", "Strong": "green"}.get(details["label"], "gray")
        self.strength_label.config(text=f"Password strength: {details['label']} ({details['score']}/5)", fg=color)

    def calculate_sha_button(self) -> None:
        file_path = self.input_path_var.get().strip()
        if not file_path:
            messagebox.showerror("Error", "Please select a file first.")
            return
        try:
            digest = calculate_sha256(file_path)
            self.sha_var.set(f"SHA-256: {digest}")
            self.status_var.set("SHA-256 calculated successfully.")
            log_activity(f"SHA-256 calculated for file: {os.path.basename(file_path)}")
        except Exception as exc:  # pragma: no cover - GUI exception path
            messagebox.showerror("Error", f"Unable to calculate SHA-256: {exc}")
            self.status_var.set("SHA-256 calculation failed.")

    def _resolve_kdf_id(self) -> int:
        choice = self.kdf_choice_var.get()
        if choice == "Argon2id":
            return ARGON2_KDF_ID
        return KDF_ID

    def _resolve_output_for_operation(self, mode: str) -> Path:
        input_path = self.input_path_var.get().strip()
        if not input_path:
            raise ValueError("Please select a file before continuing.")

        selected_output = self.output_dir_var.get().strip()
        if mode == "encrypt":
            if selected_output:
                candidate = Path(selected_output)
                if candidate.exists() and candidate.is_dir():
                    return candidate / (Path(input_path).name + ".enc")
                if candidate.suffix:
                    return candidate
                return candidate / (Path(input_path).name + ".enc")
            return Path(input_path).with_name(Path(input_path).name + ".enc")

        if mode == "decrypt":
            encrypted = Path(input_path)
            try:
                parsed = parse_sfet_header(encrypted.read_bytes())
                original_name = parsed["filename"].decode("utf-8", "surrogateescape")
            except Exception:
                original_name = Path(input_path).stem.replace(".enc", "")

            if selected_output:
                candidate = Path(selected_output)
                if candidate.exists() and candidate.is_dir():
                    return candidate / original_name
                if candidate.suffix:
                    return candidate
                return candidate / original_name
            return encrypted.with_name(original_name)

        raise ValueError("Unsupported operation.")

    def _validate_inputs(self, action: str) -> tuple[str, str, int]:
        input_path = self.input_path_var.get().strip()
        password = self.password_var.get()

        if not input_path:
            raise ValueError("Please select a file first.")
        if not password:
            raise ValueError("Please enter a password.")
        if len(password) < 8:
            raise ValueError("Use at least 8 characters for a stronger password.")

        kdf_id = self._resolve_kdf_id()
        if action == "encrypt":
            if not is_argon2_available() and kdf_id == ARGON2_KDF_ID:
                raise ValueError("Argon2id is not available in this environment. Install argon2-cffi first.")
        return input_path, password, kdf_id

    def _run_operation(self, action: str) -> None:
        try:
            input_path, password, kdf_id = self._validate_inputs(action)
            output_path = self._resolve_output_for_operation(action)
        except Exception as exc:
            messagebox.showerror("Error", str(exc))
            return

        if output_path.exists() and not messagebox.askyesno("Overwrite?", f"The output file already exists:\n{output_path}\n\nDo you want to overwrite it?"):
            self.status_var.set("Operation cancelled: output file already exists.")
            return

        self._set_busy(True)
        self.status_var.set(f"Working on {action}...")

        worker = threading.Thread(
            target=self._worker,
            args=(action, input_path, str(output_path), password, kdf_id),
            daemon=True,
        )
        worker.start()

    def _worker(self, action: str, input_path: str, output_path: str, password: str, kdf_id: int) -> None:
        try:
            if action == "encrypt":
                result = encrypt_file(input_path, output_path, password, kdf_id=kdf_id)
            else:
                result = decrypt_file(input_path, output_path, password)
            self.after(0, lambda: self._handle_result(action, result, output_path))
        except Exception as exc:  # pragma: no cover - GUI safety path
            self.after(0, lambda: self._handle_result(action, {"success": False, "message": str(exc)}, output_path))

    def _handle_result(self, action: str, result: dict, output_path: str) -> None:
        self._set_busy(False)
        if result.get("success"):
            self.status_var.set(result.get("message", "Operation completed successfully."))
            log_activity(f"File {action}ed: {Path(output_path).name}")
            if action == "decrypt":
                try:
                    original_hash = calculate_sha256(self.input_path_var.get().strip())
                    decrypted_hash = calculate_sha256(output_path)
                    verification = "PASSED" if original_hash == decrypted_hash else "FAILED"
                    self.sha_var.set(
                        f"Original File SHA-256: {original_hash}\nDecrypted File SHA-256: {decrypted_hash}\nIntegrity Verification: {verification}"
                    )
                except Exception:
                    self.sha_var.set("SHA-256: unable to verify file integrity after decryption.")
            messagebox.showinfo("Success", result.get("message", "Operation completed successfully."))
            return

        self.status_var.set(result.get("message", "Operation failed."))
        messagebox.showerror("Error", result.get("message", "Operation failed."))

    def encrypt_file(self) -> None:
        self._run_operation("encrypt")

    def decrypt_file(self) -> None:
        self._run_operation("decrypt")


def main() -> None:
    app = SecureFileApp()
    app.mainloop()
