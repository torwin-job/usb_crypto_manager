import customtkinter as ctk
import threading
import os
from tkinter import filedialog, messagebox
from usb.usb_manager import get_usb_drives, get_usb_drives_with_labels, find_all_keys_on_usb
from core import crypto, secure_delete
from gui.dialogs import PasswordDialog, ProgressDialog

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("USB Crypto Manager")
        self.geometry("720x760")
        self.resizable(False, False)
        self.configure(fg_color=("#181c26", "#23272e"))

        self.aes_var = ctk.StringVar()
        self.rsa_priv_var = ctk.StringVar()
        self.rsa_pub_var = ctk.StringVar()

        ctk.CTkLabel(self, text="USB Crypto Manager", font=("Arial", 24, "bold"), text_color="#f6ad55").pack(pady=(20, 10))

        # --- USB-устройства ---
        usb_frame = ctk.CTkFrame(self, fg_color="#23272e")
        usb_frame.pack(pady=10, fill="x", padx=30)
        ctk.CTkLabel(usb_frame, text="Выберите USB-устройство:", font=("Arial", 13), text_color="#e2e8f0").grid(row=0, column=0, padx=5, sticky="w")
        self.usb_var = ctk.StringVar()
        self.usb_menu = ctk.CTkOptionMenu(usb_frame, variable=self.usb_var, values=["Нет"], width=350, fg_color="#2b6cb0", button_color="#2c5282", text_color="#f7fafc")
        self.usb_menu.grid(row=0, column=1, padx=5, sticky="ew")
        usb_frame.grid_columnconfigure(1, weight=1)
        self.refresh_usb_btn = ctk.CTkButton(usb_frame, text="Обновить список USB", command=self.update_usb_menu, width=180, fg_color="#f6ad55", text_color="#23272e")
        self.refresh_usb_btn.grid(row=0, column=2, padx=5, sticky="e")

        # --- Папка для шифрования ---
        folder_frame = ctk.CTkFrame(self, fg_color="#23272e")
        folder_frame.pack(pady=10, fill="x", padx=30)
        ctk.CTkLabel(folder_frame, text="Папка для шифрования/дешифрования:", font=("Arial", 13), text_color="#e2e8f0").grid(row=0, column=0, padx=5, sticky="w")
        self.folder_path = ctk.CTkLabel(folder_frame, text="Не выбрана", width=500, anchor="w", text_color="#f7fafc")
        self.folder_path.grid(row=0, column=1, padx=5, sticky="ew")
        folder_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkButton(folder_frame, text="Выбрать папку", command=self.choose_folder, width=160, fg_color="#f6ad55", text_color="#23272e").grid(row=0, column=2, padx=5, sticky="e")

        # --- Выбор ключей с флешки ---
        keys_frame = ctk.CTkFrame(self, fg_color="#23272e")
        keys_frame.pack(pady=12, fill="x", padx=30)
        ctk.CTkLabel(keys_frame, text="Выбор ключей с флешки:", font=("Arial", 13, "bold"), text_color="#f6ad55").grid(row=0, column=0, columnspan=2, sticky="w", pady=(8, 6), padx=8)
        ctk.CTkLabel(keys_frame, text="AES-ключ:", font=("Arial", 12), text_color="#e2e8f0").grid(row=1, column=0, sticky="e", padx=8, pady=4)
        self.aes_menu = ctk.CTkOptionMenu(keys_frame, variable=self.aes_var, values=["Нет"], width=350, fg_color="#2b6cb0", button_color="#2c5282", text_color="#f7fafc")
        self.aes_menu.grid(row=1, column=1, sticky="ew", padx=8, pady=4)
        ctk.CTkLabel(keys_frame, text="RSA приватный ключ:", font=("Arial", 12), text_color="#e2e8f0").grid(row=2, column=0, sticky="e", padx=8, pady=4)
        self.rsa_priv_menu = ctk.CTkOptionMenu(keys_frame, variable=self.rsa_priv_var, values=["Нет"], width=350, fg_color="#2b6cb0", button_color="#2c5282", text_color="#f7fafc")
        self.rsa_priv_menu.grid(row=2, column=1, sticky="ew", padx=8, pady=4)
        ctk.CTkLabel(keys_frame, text="RSA публичный ключ:", font=("Arial", 12), text_color="#e2e8f0").grid(row=3, column=0, sticky="e", padx=8, pady=4)
        self.rsa_pub_menu = ctk.CTkOptionMenu(keys_frame, variable=self.rsa_pub_var, values=["Нет"], width=350, fg_color="#2b6cb0", button_color="#2c5282", text_color="#f7fafc")
        self.rsa_pub_menu.grid(row=3, column=1, sticky="ew", padx=8, pady=4)
        keys_frame.grid_columnconfigure(1, weight=1)

        # --- Генерация ключей ---
        gen_frame = ctk.CTkFrame(self, fg_color="#23272e")
        gen_frame.pack(pady=10, fill="x", padx=30)
        ctk.CTkLabel(gen_frame, text="Генерация ключей:", font=("Arial", 15, "bold"), text_color="#f6ad55").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.btn_gen_rsa = ctk.CTkButton(gen_frame, text="Генерировать RSA-ключи", command=self.gen_rsa_keys, width=220, fg_color="#2b6cb0", text_color="#f7fafc")
        self.btn_gen_aes = ctk.CTkButton(gen_frame, text="Генерировать AES-ключ", command=self.gen_aes_key, width=220, fg_color="#2b6cb0", text_color="#f7fafc")
        self.btn_gen_rsa.grid(row=0, column=1, padx=5, pady=2)
        self.btn_gen_aes.grid(row=0, column=2, padx=5, pady=2)
        gen_frame.grid_columnconfigure(0, weight=1)
        gen_frame.grid_columnconfigure(1, weight=0)
        gen_frame.grid_columnconfigure(2, weight=0)

        # --- Шифрование ---
        enc_frame = ctk.CTkFrame(self, fg_color="#23272e")
        enc_frame.pack(pady=10, fill="x", padx=30)
        ctk.CTkLabel(enc_frame, text="Шифрование:", font=("Arial", 15, "bold"), text_color="#f6ad55").pack(anchor="w", pady=2)
        grid_btns = ctk.CTkFrame(enc_frame, fg_color="transparent")
        grid_btns.pack(anchor="w", pady=2, fill="x")
        self.btn_encrypt_file = ctk.CTkButton(grid_btns, text="Зашифровать файл", command=self.encrypt_file, width=260, height=40, fg_color="#2b6cb0", text_color="#f7fafc")
        self.btn_encrypt_dir = ctk.CTkButton(grid_btns, text="Зашифровать папку", command=self.encrypt_dir, width=260, height=40, fg_color="#805ad5", text_color="#f7fafc")
        self.btn_decrypt_file = ctk.CTkButton(grid_btns, text="Расшифровать файл", command=self.decrypt_file, width=260, height=40, fg_color="#38a169", text_color="#f7fafc")
        self.btn_decrypt_dir = ctk.CTkButton(grid_btns, text="Расшифровать папку", command=self.decrypt_dir, width=260, height=40, fg_color="#38a169", text_color="#f7fafc")
        self.btn_encrypt_file.grid(row=0, column=0, padx=10, pady=7, sticky="ew")
        self.btn_encrypt_dir.grid(row=1, column=0, padx=10, pady=7, sticky="ew")
        self.btn_decrypt_file.grid(row=0, column=1, padx=10, pady=7, sticky="ew")
        self.btn_decrypt_dir.grid(row=1, column=1, padx=10, pady=7, sticky="ew")
        grid_btns.grid_columnconfigure(0, weight=1)
        grid_btns.grid_columnconfigure(1, weight=1)
        self.crypto_buttons = [self.btn_encrypt_file, self.btn_decrypt_file, self.btn_encrypt_dir, self.btn_decrypt_dir]

        # --- Подпись файлов ---
        sign_frame = ctk.CTkFrame(self, fg_color="#23272e")
        sign_frame.pack(pady=10, fill="x", padx=30)
        ctk.CTkLabel(sign_frame, text="Подпись:", font=("Arial", 15, "bold"), text_color="#f6ad55").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.btn_sign = ctk.CTkButton(sign_frame, text="Подписать файл", command=self.sign_file, width=200, fg_color="#805ad5", text_color="#f7fafc")
        self.btn_verify = ctk.CTkButton(sign_frame, text="Проверить подпись", command=self.verify_signature, width=200, fg_color="#805ad5", text_color="#f7fafc")
        self.btn_sign.grid(row=0, column=1, padx=5, pady=2)
        self.btn_verify.grid(row=0, column=2, padx=5, pady=2)
        sign_frame.grid_columnconfigure(0, weight=1)
        sign_frame.grid_columnconfigure(1, weight=0)
        sign_frame.grid_columnconfigure(2, weight=0)
        self.sign_buttons = [self.btn_sign, self.btn_verify]

        self.status_label = ctk.CTkLabel(self, text="", font=("Arial", 14))
        self.status_label.pack(pady=10)

        self.selected_folder = None
        self.selected_usb = None
        self.usb_keys = {'aes': [], 'rsa_priv': [], 'rsa_pub': []}
        self.set_crypto_buttons_state("disabled")
        self.set_sign_buttons_state("disabled")
        self.update_usb_menu()
        self.after(1000, self.check_usb_and_key_thread)

    def update_usb_menu(self):
        drives_with_labels = get_usb_drives_with_labels()
        self.usb_label_to_path = {}
        drives = get_usb_drives()
        for label, path in zip(drives_with_labels, drives):
            self.usb_label_to_path[label] = path
        values = drives_with_labels if drives_with_labels else ["Нет"]
        self.usb_menu.configure(values=values)
        current = self.usb_var.get()
        # Если пользовательский выбор есть в новом списке — не меняем
        if current in drives_with_labels:
            self.selected_usb = self.usb_label_to_path.get(current)
            self.on_usb_change(current)
            return
        # --- Автовыбор только если нет пользовательского выбора ---
        selected_label = None
        for label in drives_with_labels:
            path = self.usb_label_to_path[label]
            keys_dir = os.path.join(path, "crypto_keys")
            if os.path.isdir(keys_dir):
                try:
                    files = os.listdir(keys_dir)
                    for f in files:
                        if f.endswith('.key.enc') or f.endswith('.pem.enc'):
                            selected_label = label
                            break
                        if f.endswith('.pem'):
                            try:
                                with open(os.path.join(keys_dir, f), errors='ignore') as fp:
                                    if 'PUBLIC KEY' in fp.read(200):
                                        selected_label = label
                                        break
                            except Exception:
                                continue
                    if selected_label:
                        break
                except Exception:
                    continue
        if selected_label:
            self.usb_var.set(selected_label)
            self.selected_usb = self.usb_label_to_path[selected_label]
        elif drives_with_labels:
            self.usb_var.set(drives_with_labels[0])
            self.selected_usb = self.usb_label_to_path[drives_with_labels[0]]
        else:
            self.usb_var.set("Нет")
            self.selected_usb = None
        self.on_usb_change(self.usb_var.get())

    def on_usb_change(self, value):
        self.selected_usb = self.usb_label_to_path.get(value) if value != "Нет" else None
        self.update_keys_from_usb()

    def update_keys_from_usb(self):
        if not self.selected_usb:
            self.usb_keys = {'aes': [], 'rsa_priv': [], 'rsa_pub': []}
        else:
            from usb.usb_manager import find_keys_on_usb
            self.usb_keys = find_keys_on_usb(self.selected_usb, keys_dir="crypto_keys")
        self.update_key_menus()

    def choose_folder(self):
        folder = filedialog.askdirectory(title="Выбрать папку для шифрования/дешифрования")
        if folder:
            self.selected_folder = folder
            self.folder_path.configure(text=folder)

    def update_key_menus(self):
        prev_aes = self.aes_var.get()
        prev_priv = self.rsa_priv_var.get()
        prev_pub = self.rsa_pub_var.get()
        aes = [k for k in self.usb_keys['aes'] if k.endswith('.enc')] if self.usb_keys['aes'] else ["Нет"]
        rsa_priv = [k for k in self.usb_keys['rsa_priv'] if k.endswith('.pem.enc')] if self.usb_keys['rsa_priv'] else ["Нет"]
        rsa_pub = self.usb_keys['rsa_pub'] if self.usb_keys['rsa_pub'] else ["Нет"]
        if not aes:
            aes = ["Нет"]
        if not rsa_priv:
            rsa_priv = ["Нет"]
        if not rsa_pub:
            rsa_pub = ["Нет"]
        self.aes_menu.configure(values=aes)
        self.rsa_priv_menu.configure(values=rsa_priv)
        self.rsa_pub_menu.configure(values=rsa_pub)
        self.aes_var.set(aes[0])
        self.rsa_priv_var.set(rsa_priv[0])
        self.rsa_pub_var.set(rsa_pub[0])

    def set_crypto_buttons_state(self, state):
        for btn in self.crypto_buttons:
            btn.configure(state=state)

    def set_sign_buttons_state(self, state):
        for btn in self.sign_buttons:
            btn.configure(state=state)

    def check_usb_and_key_thread(self):
        drives = get_usb_drives()
        if not drives:
            self.status_label.configure(text="USB-накопители не найдены", text_color="#e74c3c")
            self.set_crypto_buttons_state("disabled")
            self.set_sign_buttons_state("disabled")
            self.usb_keys = {'aes': [], 'rsa_priv': [], 'rsa_pub': []}
            self.update_key_menus()
        else:
            self.status_label.configure(text=f"USB-накопители: {', '.join(drives)}", text_color="#1abc9c")
            self.set_crypto_buttons_state("normal")
            self.set_sign_buttons_state("normal")
            self.update_usb_menu()
        self.after(3000, self.check_usb_and_key_thread)

    def gen_rsa_keys(self):
        drive = self.selected_usb
        if not drive:
            messagebox.showwarning("Внимание", "Сначала выберите USB-устройство!")
            return
        keys_dir = os.path.join(drive, "crypto_keys")
        os.makedirs(keys_dir, exist_ok=True)
        name = ctk.CTkInputDialog(text="Введите название ключа (латиницей, без пробелов):", title="Имя ключа").get_input()
        if not name:
            messagebox.showwarning("Внимание", "Имя ключа не задано!")
            return
        import datetime
        dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        priv_path = os.path.join(keys_dir, f"rsa_private_{name}_{dt}.pem")
        pub_path = os.path.join(keys_dir, f"rsa_public_{name}_{dt}.pem")
        password = self.get_password()
        priv_final, pub_final = crypto.generate_rsa_keypair(priv_path, pub_path, password if password else None)
        messagebox.showinfo("Готово", f"RSA-ключи сохранены: {priv_final}, {pub_final}")
        self.update_keys_from_usb()
        # Выставляем выбор на только что созданные ключи
        enc_priv = priv_final + ".enc" if os.path.exists(priv_final + ".enc") else priv_final
        self.rsa_priv_var.set(enc_priv if enc_priv in self.rsa_priv_menu.cget('values') else self.rsa_priv_menu.cget('values')[0])
        self.rsa_pub_var.set(pub_final if pub_final in self.rsa_pub_menu.cget('values') else self.rsa_pub_menu.cget('values')[0])

    def gen_aes_key(self):
        drive = self.selected_usb
        if not drive:
            messagebox.showwarning("Внимание", "Сначала выберите USB-устройство!")
            return
        keys_dir = os.path.join(drive, "crypto_keys")
        os.makedirs(keys_dir, exist_ok=True)
        name = ctk.CTkInputDialog(text="Введите название AES-ключа (латиницей, без пробелов):", title="Имя ключа").get_input()
        if not name:
            messagebox.showwarning("Внимание", "Имя ключа не задано!")
            return
        import datetime
        dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        key_path = os.path.join(keys_dir, f"aes_{name}_{dt}.key")
        password = self.get_password()
        enc_path = crypto.generate_aes_key(key_path, password=password if password else None)
        messagebox.showinfo("Готово", f"AES-ключ сохранён: {enc_path}")
        self.update_keys_from_usb()
        # Выставляем выбор на только что созданный ключ
        enc_key = enc_path if enc_path in self.aes_menu.cget('values') else self.aes_menu.cget('values')[0]
        self.aes_var.set(enc_key)

    def encrypt_file(self):
        key = self.aes_var.get() if self.aes_var.get() != "Нет" else filedialog.askopenfilename(title="Выбрать AES-ключ", filetypes=[("Encrypted Key files", "*.enc")])
        file = filedialog.askopenfilename(title="Выбрать файл для шифрования")
        if key and file and os.path.exists(key):
            if not self.check_key_integrity(key):
                return
            password = self.get_aes_password()
            tmp_key_path = os.path.splitext(key)[0]
            try:
                crypto.decrypt_file_with_password(key, tmp_key_path, password)
            except ValueError:
                messagebox.showerror("Ошибка", "Неверный пароль или ключ, либо файл повреждён!")
                return
            dlg = ProgressDialog(self, title="Шифрование файла...")
            dlg.set_progress(0.1)
            out = crypto.encrypt_file(tmp_key_path, file)
            os.remove(tmp_key_path)
            dlg.set_progress(1.0)
            self.after(300, dlg.destroy)
            messagebox.showinfo("Готово", f"Зашифровано: {out}")
            if messagebox.askyesno("Удалить исходный файл?", "Удалить исходный файл после шифрования безопасно?"):
                self.secure_delete(file)

    def decrypt_file(self):
        key = self.aes_var.get() if self.aes_var.get() != "Нет" else filedialog.askopenfilename(title="Выбрать AES-ключ", filetypes=[("Encrypted Key files", "*.enc")])
        file = filedialog.askopenfilename(title="Выбрать файл для расшифровки", filetypes=[("Encrypted files", "*.enc")])
        if key and file and os.path.exists(key):
            if not self.check_key_integrity(key):
                return
            password = self.get_aes_password()
            tmp_key_path = os.path.splitext(key)[0]
            try:
                crypto.decrypt_file_with_password(key, tmp_key_path, password)
            except ValueError:
                messagebox.showerror("Ошибка", "Неверный пароль или ключ, либо файл повреждён!")
                return
            dlg = ProgressDialog(self, title="Расшифровка файла...")
            dlg.set_progress(0.1)
            try:
                out = crypto.decrypt_file(tmp_key_path, file)
            except ValueError as e:
                dlg.destroy()
                messagebox.showerror("Ошибка расшифровки", str(e))
                os.remove(tmp_key_path)
                return
            os.remove(tmp_key_path)
            dlg.set_progress(1.0)
            self.after(300, dlg.destroy)
            messagebox.showinfo("Готово", f"Расшифровано: {out}")
            if messagebox.askyesno("Удалить исходный файл?", "Удалить исходный файл после расшифровки безопасно?"):
                self.secure_delete(file)

    def encrypt_dir(self):
        key = self.aes_var.get() if self.aes_var.get() != "Нет" else filedialog.askopenfilename(title="Выбрать AES-ключ", filetypes=[("Encrypted Key files", "*.enc")])
        if not self.selected_folder:
            messagebox.showwarning("Внимание", "Сначала выберите папку!")
            return
        if key and self.selected_folder and os.path.exists(key):
            if not self.check_key_integrity(key):
                return
            password = self.get_aes_password()
            tmp_key_path = os.path.splitext(key)[0]
            try:
                crypto.decrypt_file_with_password(key, tmp_key_path, password)
            except ValueError:
                messagebox.showerror("Ошибка", "Неверный пароль или ключ, либо файл повреждён!")
                return
            total = sum(len(files) for _, _, files in os.walk(self.selected_folder))
            done = 0
            dlg = ProgressDialog(self, title="Шифрование папки...")
            dlg.set_progress(0)
            for root, _, files in os.walk(self.selected_folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    crypto.encrypt_file(tmp_key_path, file_path)
                    done += 1
                    dlg.set_progress(done / total)
            os.remove(tmp_key_path)
            dlg.set_progress(1.0)
            self.after(300, dlg.destroy)
            messagebox.showinfo("Готово", f"Директория зашифрована: {self.selected_folder}")
            if messagebox.askyesno("Удалить исходные файлы?", "Удалить все исходные файлы в папке после шифрования безопасно?"):
                for root, _, files in os.walk(self.selected_folder):
                    for file in files:
                        if not file.endswith('.enc'):
                            self.secure_delete(os.path.join(root, file))

    def decrypt_dir(self):
        key = self.aes_var.get() if self.aes_var.get() != "Нет" else filedialog.askopenfilename(title="Выбрать AES-ключ", filetypes=[("Encrypted Key files", "*.enc")])
        if not self.selected_folder:
            messagebox.showwarning("Внимание", "Сначала выберите папку!")
            return
        if key and self.selected_folder and os.path.exists(key):
            if not self.check_key_integrity(key):
                return
            password = self.get_aes_password()
            tmp_key_path = os.path.splitext(key)[0]
            try:
                crypto.decrypt_file_with_password(key, tmp_key_path, password)
            except ValueError:
                messagebox.showerror("Ошибка", "Неверный пароль или ключ, либо файл повреждён!")
                return
            total = sum(1 for root, _, files in os.walk(self.selected_folder) for file in files if file.endswith('.enc'))
            done = 0
            dlg = ProgressDialog(self, title="Расшифровка папки...")
            dlg.set_progress(0)
            errors = []
            for root, _, files in os.walk(self.selected_folder):
                for file in files:
                    if file.endswith('.enc'):
                        file_path = os.path.join(root, file)
                        try:
                            crypto.decrypt_file(tmp_key_path, file_path)
                        except Exception as e:
                            errors.append(f"{file}: {e}")
                        done += 1
                        dlg.set_progress(done / total if total else 1)
            os.remove(tmp_key_path)
            dlg.set_progress(1.0)
            self.after(300, dlg.destroy)
            if errors:
                messagebox.showerror("Ошибки при расшифровке", "\n".join(errors))
            else:
                messagebox.showinfo("Готово", f"Директория расшифрована: {self.selected_folder}")
            if messagebox.askyesno("Удалить исходные файлы?", "Удалить все исходные файлы в папке после расшифровки безопасно?"):
                for root, _, files in os.walk(self.selected_folder):
                    for file in files:
                        if file.endswith('.enc'):
                            self.secure_delete(os.path.join(root, file))

    def sign_file(self):
        priv = self.rsa_priv_var.get() if self.rsa_priv_var.get() != "Нет" else filedialog.askopenfilename(title="Выбрать приватный ключ", filetypes=[("PEM files", "*.pem"), ("Encrypted PEM", "*.enc")])
        file = filedialog.askopenfilename(title="Выбрать файл для подписи")
        if priv and file and os.path.exists(priv):
            if not self.check_key_integrity(priv):
                return
            if priv.endswith('.enc'):
                password = self.get_password()
            else:
                password = ctk.CTkInputDialog(text="Пароль для приватного ключа (если есть):", title="Пароль").get_input()
            with open(file, 'rb') as f:
                data = f.read()
            sig = crypto.sign_data(priv, data, password if password else None)
            sig_file = file + '.sig'
            with open(sig_file, 'w') as f:
                f.write(sig)
            messagebox.showinfo("Готово", f"Подпись сохранена в {sig_file}")

    def verify_signature(self):
        pub = self.rsa_pub_var.get() if self.rsa_pub_var.get() != "Нет" else filedialog.askopenfilename(title="Выбрать публичный ключ", filetypes=[("PEM files", "*.pem")])
        file = filedialog.askopenfilename(title="Выбрать файл для проверки")
        sig_file = filedialog.askopenfilename(title="Выбрать файл с подписью", filetypes=[("Signature files", "*.sig")])
        if pub and file and sig_file and os.path.exists(pub):
            if not self.check_key_integrity(pub):
                return
            with open(file, 'rb') as f:
                data = f.read()
            with open(sig_file, 'r') as f:
                sig = f.read()
            ok = crypto.verify_signature(pub, data, sig)
            messagebox.showinfo("Результат", "Подпись верна" if ok else "Подпись НЕВЕРНА!")

    def check_key_integrity(self, path):
        res = crypto.check_file_hash(path)
        if res is None:
            messagebox.showwarning("Внимание", f"Для ключа {path} не найден файл хэша (.sha256). Целостность не гарантируется!")
            return True
        if not res:
            messagebox.showerror("Ошибка", f"Целостность ключа {path} нарушена! Операция отменена.")
            return False
        return True

    def get_password(self):
        dlg = PasswordDialog(self)
        return dlg.get_password()

    def get_aes_password(self):
        return self.get_password()

    def secure_delete(self, path, passes=3):
        try:
            secure_delete.secure_delete(path, passes)
        except Exception as e:
            messagebox.showwarning("Ошибка удаления", f"Не удалось безопасно удалить файл {path}: {e}") 