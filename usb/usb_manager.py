import psutil
import os
import sys
import getpass
import ctypes
from typing import List, Optional, Dict

def get_usb_drives() -> List[str]:
    if sys.platform == 'win32':
        usb_drives = []
        for part in psutil.disk_partitions(all=False):
            if 'removable' in part.opts.lower() or part.fstype == '':
                usb_drives.append(part.device)
        return usb_drives
    else:
        # Linux: ищем флешки в /media/USERNAME/ и /run/media/USERNAME/
        usb_drives = []
        user = getpass.getuser()
        for part in psutil.disk_partitions(all=False):
            if part.mountpoint.startswith(f'/media/{user}/') or part.mountpoint.startswith(f'/run/media/{user}/'):
                usb_drives.append(part.mountpoint)
        return usb_drives

def get_usb_drives_with_labels() -> List[str]:
    drives = get_usb_drives()
    if sys.platform == 'win32':
        result = []
        for drive in drives:
            label: Optional[str] = None
            try:
                vol_buf = ctypes.create_unicode_buffer(1024)
                fs_buf = ctypes.create_unicode_buffer(1024)
                serial = ctypes.c_ulong()
                maxlen = ctypes.c_ulong()
                flags = ctypes.c_ulong()
                ctypes.windll.kernel32.GetVolumeInformationW(
                    ctypes.c_wchar_p(drive),
                    vol_buf,
                    ctypes.sizeof(vol_buf),
                    ctypes.byref(serial),
                    ctypes.byref(maxlen),
                    ctypes.byref(flags),
                    fs_buf,
                    ctypes.sizeof(fs_buf)
                )
                label = vol_buf.value
            except Exception:
                label = None
            if label:
                result.append(f"{label} ({drive})")
            else:
                result.append(drive)
        return result
    else:
        # Linux: метка = имя папки монтирования
        return [os.path.basename(d) + f" ({d})" for d in drives]

def find_usb_key(key_filename: str = "aes.key") -> Optional[str]:
    for drive in get_usb_drives():
        key_path = os.path.join(drive, key_filename)
        if os.path.exists(key_path):
            return key_path
    return None

def find_all_keys_on_usb(keys_dir: str = "crypto_keys") -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {'aes': [], 'rsa_priv': [], 'rsa_pub': []}
    for drive in get_usb_drives():
        dir_path = os.path.join(drive, keys_dir)
        if os.path.isdir(dir_path):
            for fname in os.listdir(dir_path):
                fpath = os.path.join(dir_path, fname)
                if fname.endswith('.key.enc'):
                    result['aes'].append(fpath)
                elif fname.endswith('.pem.enc'):
                    result['rsa_priv'].append(fpath)
                elif fname.endswith('.pem'):
                    try:
                        with open(fpath, 'r') as f:
                            content = f.read(200)
                            if 'PUBLIC KEY' in content:
                                result['rsa_pub'].append(fpath)
                    except Exception:
                        continue
    return result

def find_keys_on_usb(usb_path: str, keys_dir: str = "crypto_keys") -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {'aes': [], 'rsa_priv': [], 'rsa_pub': []}
    dir_path = os.path.join(usb_path, keys_dir)
    if os.path.isdir(dir_path):
        for fname in os.listdir(dir_path):
            fpath = os.path.join(dir_path, fname)
            if fname.endswith('.key.enc'):
                result['aes'].append(fpath)
            elif fname.endswith('.pem.enc'):
                result['rsa_priv'].append(fpath)
            elif fname.endswith('.pem'):
                try:
                    with open(fpath, 'r') as f:
                        content = f.read(200)
                        if 'PUBLIC KEY' in content:
                            result['rsa_pub'].append(fpath)
                except Exception:
                    pass
    return result 