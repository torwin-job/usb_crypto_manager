import tkinter as tk
from tkinter import simpledialog
import customtkinter as ctk

class PasswordInputDialog(ctk.CTkInputDialog):
    def __init__(self, parent=None, title="Пароль"):
        super().__init__(text="Введите пароль для приватного ключа:", title=title)

    def get_input(self):
        # поле entry создается только после вызова super().get_input()
        value = super().get_input()
        try:
            self.entry.configure(show="*")
        except Exception:
            pass
        return value


def get_password(parent, title="Пароль"):
    dlg = PasswordInputDialog(parent, title)
    return dlg.get_input()

class ProgressDialog(ctk.CTkToplevel):
    def __init__(self, parent, title="Выполняется операция..."):
        super().__init__(parent)
        self.title(title)
        self.geometry("350x80")
        self.resizable(False, False)
        ctk.CTkLabel(self, text=title, font=("Arial", 13)).pack(pady=8)
        self.progress = ctk.CTkProgressBar(self, width=300)
        self.progress.pack(pady=8)
        self.progress.set(0)
        self.update_idletasks()

    def set_progress(self, value):
        self.progress.set(value)
        self.update_idletasks() 