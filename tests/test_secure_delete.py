import os
import tempfile
from core.secure_delete import secure_delete

def test_secure_delete_removes_file():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b'12345')
        path = f.name
    assert os.path.exists(path)
    secure_delete(path)
    assert not os.path.exists(path)

def test_secure_delete_nonexistent_file():
    # Не должно быть ошибки
    secure_delete("definitely_not_exists_123456789.txt")

def test_secure_delete_multiple_passes(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_bytes(b"test")
    secure_delete(str(file_path), passes=5)
    assert not file_path.exists() 