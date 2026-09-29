"""Tkinter GUI compatibility wrapper for the Secure File Encryption Tool."""

from ui.main_window import SecureFileApp


def main() -> None:
    app = SecureFileApp()
    app.mainloop()
