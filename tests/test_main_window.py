import pytest
import types
from unittest import mock
from gui.main_window import App

@pytest.fixture
def app(monkeypatch):
    # Мокаем все messagebox и filedialog, чтобы не было реальных окон
    monkeypatch.setattr("tkinter.messagebox.showwarning", lambda *a, **k: None)
    monkeypatch.setattr("tkinter.messagebox.showinfo", lambda *a, **k: None)
    monkeypatch.setattr("tkinter.messagebox.showerror", lambda *a, **k: None)
    monkeypatch.setattr("tkinter.filedialog.askopenfilename", lambda *a, **k: "fakefile")
    monkeypatch.setattr("tkinter.filedialog.askdirectory", lambda *a, **k: "fakefolder")
    # Мокаем customtkinter диалоги
    monkeypatch.setattr("gui.dialogs.PasswordDialog", lambda *a, **k: types.SimpleNamespace(get_password=lambda: "1234"))
    monkeypatch.setattr("gui.dialogs.ProgressDialog", lambda *a, **k: types.SimpleNamespace(set_progress=lambda v: None, destroy=lambda: None))
    return App()

def test_update_usb_menu_sets_usb_var(app):
    app.usb_label_to_path = {"USB1": "D:/", "USB2": "E:/"}
    app.usb_menu.configure(values=["USB1", "USB2"])
    app.usb_var.set("USB1")
    app.update_usb_menu()
    # Проверяем, что выбранное значение — либо путь, либо 'Нет'
    assert app.usb_var.get().replace("\\", "/") in ["D:/", "E:/", "Нет"]

def test_choose_folder_sets_selected_folder(app):
    app.choose_folder()
    assert app.selected_folder == "fakefolder"
    assert app.folder_path.cget("text") == "fakefolder"

def test_check_key_integrity_true(app, monkeypatch):
    monkeypatch.setattr("core.crypto.check_file_hash", lambda path: True)
    assert app.check_key_integrity("somefile") is True

def test_check_key_integrity_false(app, monkeypatch):
    monkeypatch.setattr("core.crypto.check_file_hash", lambda path: False)
    called = {}
    def fake_showerror(title, msg):
        called["err"] = True
    monkeypatch.setattr("tkinter.messagebox.showerror", fake_showerror)
    assert app.check_key_integrity("somefile") is False
    assert called.get("err")

def test_check_key_integrity_none(app, monkeypatch):
    monkeypatch.setattr("core.crypto.check_file_hash", lambda path: None)
    called = {}
    def fake_showwarning(title, msg):
        called["warn"] = True
    monkeypatch.setattr("tkinter.messagebox.showwarning", fake_showwarning)
    assert app.check_key_integrity("somefile") is True
    assert called.get("warn")

def test_check_usb_and_key_thread_no_drives(app, monkeypatch):
    monkeypatch.setattr("gui.main_window.get_usb_drives", lambda: [])
    called = {}
    def fake_configure(**kwargs):
        called.update(kwargs)
    app.status_label.configure = fake_configure
    app.set_crypto_buttons_state = lambda state: called.setdefault("crypto", state)
    app.set_sign_buttons_state = lambda state: called.setdefault("sign", state)
    app.update_key_menus = lambda: called.setdefault("menus", True)
    app.check_usb_and_key_thread()
    assert called.get("text") == "USB-накопители не найдены"
    assert called.get("crypto") == "disabled"
    assert called.get("sign") == "disabled"
    assert called.get("menus") is True

def test_check_usb_and_key_thread_with_drives(app, monkeypatch):
    monkeypatch.setattr("gui.main_window.get_usb_drives", lambda: ["D:/"])
    called = {}
    def fake_configure(**kwargs):
        called.update(kwargs)
    app.status_label.configure = fake_configure
    app.set_crypto_buttons_state = lambda state: called.setdefault("crypto", state)
    app.set_sign_buttons_state = lambda state: called.setdefault("sign", state)
    app.update_keys_from_usb = lambda: called.setdefault("update_keys", True)
    app.check_usb_and_key_thread()
    assert "USB-накопители" in called.get("text", "")
    assert called.get("crypto") == "normal"
    assert called.get("sign") == "normal"
    assert called.get("update_keys") is True

def test_gen_rsa_keys_no_usb(app, monkeypatch):
    app.selected_usb = None
    called = {}
    monkeypatch.setattr("tkinter.messagebox.showwarning", lambda title, msg: called.setdefault("warn", msg))
    app.gen_rsa_keys()
    assert "Сначала выберите USB-устройство" in called.get("warn", "")

def test_gen_aes_key_no_usb(app, monkeypatch):
    app.selected_usb = None
    called = {}
    monkeypatch.setattr("tkinter.messagebox.showwarning", lambda title, msg: called.setdefault("warn", msg))
    app.gen_aes_key()
    assert "Сначала выберите USB-устройство" in called.get("warn", "")

def test_encrypt_dir_no_folder(app, monkeypatch):
    app.selected_folder = None
    called = {}
    monkeypatch.setattr("tkinter.messagebox.showwarning", lambda title, msg: called.setdefault("warn", msg))
    app.encrypt_dir()
    assert "Сначала выберите папку" in called.get("warn", "")

def test_secure_delete_error(app, monkeypatch):
    def raise_exc(*a, **k): raise Exception("fail")
    monkeypatch.setattr("core.secure_delete.secure_delete", raise_exc)
    called = {}
    monkeypatch.setattr("tkinter.messagebox.showwarning", lambda title, msg: called.setdefault("warn", msg))
    app.secure_delete("file.txt")
    assert "Не удалось безопасно удалить файл" in called.get("warn", "")

def test_get_password(app):
    assert app.get_password() == "1234"

def test_get_aes_password(app):
    assert app.get_aes_password() == "1234"

def test_update_key_menus_sets_values(app):
    app.usb_keys = {
        'aes': ['key1.enc', 'key2.enc'],
        'rsa_priv': ['priv1.pem.enc'],
        'rsa_pub': ['pub1.pem']
    }
    app.aes_var.set("Нет")
    app.rsa_priv_var.set("Нет")
    app.rsa_pub_var.set("Нет")
    app.update_key_menus()
    assert app.aes_var.get() == "key1.enc"
    assert app.rsa_priv_var.get() == "priv1.pem.enc"
    assert app.rsa_pub_var.get() == "pub1.pem" 