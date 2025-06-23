import os
import random

def secure_delete(path: str, passes: int = 3) -> None:
    if not os.path.isfile(path):
        return
    length = os.path.getsize(path)
    with open(path, 'ba+', buffering=0) as delfile:
        for _ in range(passes):
            delfile.seek(0)
            delfile.write(os.urandom(length))
    os.remove(path) 