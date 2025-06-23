import os
import tempfile
import pytest
from core import crypto

def test_derive_key_from_password():
    password = 'testpass'
    salt = os.urandom(16)
    key1 = crypto.derive_key_from_password(password, salt)
    key2 = crypto.derive_key_from_password(password, salt)
    assert key1 == key2
    assert len(key1) == 32

def test_encrypt_decrypt_file_with_password():
    password = 'testpass'
    data = b'hello world!'
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        in_path = f.name
    out_enc = in_path + '.enc'
    out_dec = in_path + '.dec'
    crypto.encrypt_file_with_password(in_path, out_enc, password)
    crypto.decrypt_file_with_password(out_enc, out_dec, password)
    with open(out_dec, 'rb') as f:
        assert f.read() == data
    os.remove(in_path)
    os.remove(out_enc)
    os.remove(out_dec)

def test_generate_rsa_keypair_and_sign_verify():
    with tempfile.TemporaryDirectory() as tmpdir:
        priv = os.path.join(tmpdir, 'priv.pem')
        pub = os.path.join(tmpdir, 'pub.pem')
        priv_path, pub_path = crypto.generate_rsa_keypair(priv, pub)
        data = b'data to sign'
        signature = crypto.sign_data(priv_path, data)
        assert crypto.verify_signature(pub_path, data, signature)

def test_generate_aes_key_and_encrypt_decrypt_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, 'aes.key')
        file_path = os.path.join(tmpdir, 'data.txt')
        with open(file_path, 'wb') as f:
            f.write(b'abc123')
        aes_path = crypto.generate_aes_key(key_path)
        enc_path = crypto.encrypt_file(aes_path, file_path)
        dec_path = crypto.decrypt_file(aes_path, enc_path)
        with open(dec_path, 'rb') as f:
            assert f.read() == b'abc123'

def test_hash_file_sha256():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b'12345')
        path = f.name
    h = crypto.hash_file_sha256(path)
    assert isinstance(h, str)
    assert len(h) == 64
    os.remove(path)

def test_decrypt_file_with_wrong_password(tmp_path):
    data = b"secret"
    file_path = tmp_path / "data.txt"
    file_path.write_bytes(data)
    enc_path = tmp_path / "data.txt.enc"
    crypto.encrypt_file_with_password(str(file_path), str(enc_path), "rightpass")
    dec_path = tmp_path / "data.txt.dec"
    with pytest.raises(Exception):
        crypto.decrypt_file_with_password(str(enc_path), str(dec_path), "wrongpass")

def test_sign_and_verify_wrong_data(tmp_path):
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    priv_path, pub_path = crypto.generate_rsa_keypair(str(priv), str(pub))
    data = b"original"
    signature = crypto.sign_data(priv_path, data)
    assert not crypto.verify_signature(pub_path, b"other", signature)

def test_save_and_check_file_hash(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_bytes(b"hashme")
    crypto.save_file_hash(str(file_path))
    assert crypto.check_file_hash(str(file_path)) is True
    file_path.write_bytes(b"corrupted")
    assert crypto.check_file_hash(str(file_path)) is False

def test_encrypt_decrypt_directory(tmp_path):
    dir_path = tmp_path / "dir"
    dir_path.mkdir()
    (dir_path / "a.txt").write_text("A")
    (dir_path / "b.txt").write_text("B")
    key_path = tmp_path / "aes.key"
    crypto.generate_aes_key(str(key_path))
    crypto.encrypt_directory(str(key_path), str(dir_path))
    assert any(f.suffix == ".enc" for f in dir_path.iterdir())
    crypto.decrypt_directory(str(key_path), str(dir_path))
    assert (dir_path / "a.txt").read_text() == "A"
    assert (dir_path / "b.txt").read_text() == "B"

def test_generate_aes_key_with_password(tmp_path):
    key_path = tmp_path / "aes.key"
    enc_path = crypto.generate_aes_key(str(key_path), password="1234")
    assert enc_path.endswith(".enc")
    assert os.path.exists(enc_path)

def test_generate_rsa_keypair_with_password(tmp_path):
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    priv_path, pub_path = crypto.generate_rsa_keypair(str(priv), str(pub), password="1234")
    assert priv_path.endswith(".enc")
    assert os.path.exists(priv_path)
    assert os.path.exists(pub_path)

def test_decrypt_file_returns_path(tmp_path):
    key_path = tmp_path / "aes.key"
    file_path = tmp_path / "data.txt"
    file_path.write_bytes(b"abc")
    crypto.generate_aes_key(str(key_path))
    enc_path = crypto.encrypt_file(str(key_path), str(file_path))
    out_path = crypto.decrypt_file(str(key_path), enc_path)
    assert os.path.exists(out_path)
    assert out_path.endswith(".txt")

def test_verify_signature_false_for_wrong_signature(tmp_path):
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    priv_path, pub_path = crypto.generate_rsa_keypair(str(priv), str(pub))
    data = b"data"
    signature = crypto.sign_data(priv_path, data)
    bad_signature = signature[:-2] + "ab"
    assert not crypto.verify_signature(pub_path, data, bad_signature) 