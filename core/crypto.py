import os
import base64
import tempfile
from typing import Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac

# === Вспомогательная функция для получения AES-ключа из пароля ===
def derive_key_from_password(password: str, salt: bytes, length: int = 32) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# === Шифрование файла с помощью AES (CBC) ===
def encrypt_file_with_password(file_path: str, out_path: str, password: str) -> None:
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    with open(file_path, 'rb') as f:
        data = f.read()
    padded_data = padder.update(data) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    with open(out_path, 'wb') as f:
        f.write(salt + iv + encrypted)

def decrypt_file_with_password(enc_path: str, out_path: str, password: str) -> None:
    with open(enc_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted = f.read()
    key = derive_key_from_password(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    with open(out_path, 'wb') as f:
        f.write(data)

def generate_rsa_keypair(path_private: str, path_public: str, password: Optional[str] = None) -> Tuple[str, str]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        tmp_path = tmp.name
    if password:
        encrypt_file_with_password(tmp_path, path_private + '.enc', password)
        os.remove(tmp_path)
        priv_path_final = path_private + '.enc'
        save_file_hash(priv_path_final)
    else:
        os.rename(tmp_path, path_private)
        priv_path_final = path_private
        save_file_hash(priv_path_final)
    public_key = private_key.public_key()
    with open(path_public, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    save_file_hash(path_public)
    return priv_path_final, path_public

def generate_aes_key(path: str, key_size: int = 32, password: Optional[str] = None) -> str:
    key = os.urandom(key_size)
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(key)
        tmp_path = tmp.name
    if password:
        encrypt_file_with_password(tmp_path, path + '.enc', password)
        os.remove(tmp_path)
        save_file_hash(path + '.enc')
        return path + '.enc'
    else:
        os.rename(tmp_path, path)
        save_file_hash(path)
        return path

def load_aes_key(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()

def hash_file_sha256(path: str) -> str:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            digest.update(chunk)
    return digest.finalize().hex()

def save_file_hash(path: str) -> None:
    h = hash_file_sha256(path)
    with open(path + '.sha256', 'w') as f:
        f.write(h)

def check_file_hash(path: str) -> Optional[bool]:
    if not os.path.exists(path + '.sha256'):
        return None
    with open(path + '.sha256', 'r') as f:
        saved = f.read().strip()
    actual = hash_file_sha256(path)
    return saved == actual

def sign_data(private_key_path: str, data: bytes, password: Optional[str] = None) -> str:
    if private_key_path.endswith('.enc') and password:
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        decrypt_file_with_password(private_key_path, tmp_path, password)
        with open(tmp_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        os.remove(tmp_path)
    else:
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=password.encode() if password else None,
                backend=default_backend()
            )
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_signature(public_key_path: str, data: bytes, signature_b64: str) -> bool:
    with open(public_key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def encrypt_file(aes_key_path: str, file_path: str) -> str:
    key = load_aes_key(aes_key_path)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    with open(file_path, 'rb') as f:
        data = f.read()
    padded_data = padder.update(data) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    with open(file_path + '.enc', 'wb') as f:
        f.write(iv + encrypted)
    return file_path + '.enc'

def decrypt_file(aes_key_path: str, file_path_enc: str) -> str:
    key = load_aes_key(aes_key_path)
    with open(file_path_enc, 'rb') as f:
        iv = f.read(16)
        encrypted = f.read()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    out_path = file_path_enc[:-4] if file_path_enc.endswith('.enc') else file_path_enc + '.dec'
    with open(out_path, 'wb') as f:
        f.write(data)
    return out_path

def encrypt_directory(aes_key_path: str, dir_path: str) -> None:
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            path = os.path.join(root, file)
            encrypt_file(aes_key_path, path)

def decrypt_directory(aes_key_path: str, dir_path: str) -> None:
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            if file.endswith('.enc'):
                path = os.path.join(root, file)
                decrypt_file(aes_key_path, path) 