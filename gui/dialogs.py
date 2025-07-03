import customtkinter as ctk

class PasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent, title="Пароль"):
        super().__init__(parent)
        self.title(title)
        self.geometry("300x120")
        self.resizable(False, False)
        self.grab_set()
        ctk.CTkLabel(self, text="Введите пароль для приватного ключа:").pack(pady=10)
        self.entry = ctk.CTkEntry(self, show="*")
        self.entry.pack(pady=5)
        self.ok_btn = ctk.CTkButton(self, text="OK", command=self.on_ok)
        self.ok_btn.pack(pady=5)
        self.password = None
        self.entry.bind('<Return>', lambda e: self.on_ok())
        self.entry.focus_set()
        self.wait_window(self)

    def on_ok(self):
        self.password = self.entry.get()
        self.destroy()

    def get_password(self):
        return self.password

class ProgressDialog(ctk.CTkToplevel):
    def __init__(self, parent, title="Выполняется операция..."):
        super().__init__(parent)
        self.title(title)
        self.geometry("400x120")
        self.resizable(False, False)
        self.grab_set()
        ctk.CTkLabel(self, text=title, font=("Arial", 14)).pack(pady=10)
        self.progress = ctk.CTkProgressBar(self, width=350)
        self.progress.pack(pady=10)
        self.progress.set(0)
        self.update_idletasks()

    def set_progress(self, value):
        self.progress.set(value)
        self.update_idletasks() 