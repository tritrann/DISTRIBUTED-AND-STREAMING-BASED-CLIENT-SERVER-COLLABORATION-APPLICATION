import json
import secrets
import hashlib

PBKDF2_ITERATIONS = 100000
SALT_SIZE = 16

def hash_password(password: bytes, salt: bytes) ->bytes:
    check_hash_bytes = hashlib.pbkdf2_hmac("sha256", password, salt, PBKDF2_ITERATIONS)
    return check_hash_bytes
    

def verify_user(user_dict: dict ,username: str, password: str) -> bool:
    user = user_dict.get(username)
    if user is None:
        return False
    password_bytes = password.encode("utf-8")
    salt_key = user["salt"]
    salt_bytes = bytes.fromhex(salt_key)
    hash_key = user["hash"]
    hash_bytes = bytes.fromhex(hash_key)
    check_hash_bytes = hash_password(password_bytes, salt_bytes)
    is_valid = secrets.compare_digest(hash_bytes, check_hash_bytes)
    return is_valid

def create_user_record(password: str) -> dict:
    password_bytes = password.encode("utf-8")
    salt = secrets.token_bytes(SALT_SIZE)
    password_hash = hash_password(password_bytes, salt)
    salt = salt.hex()
    password_hash= password_hash.hex()
    user = {
        "salt": salt,
        "hash": password_hash
    }
    return user

def load_users(path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            users_dict = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] {path} not found ")
        return {}
    except json.JSONDecodeError as e:
        print(f"[ERROR] '{path}' is corrupted (invalid JSON at line {e.lineno}, col {e.colno}). ")
        raise ValueError(f"'{path}' is corrupted" ) from e
    if not isinstance(users_dict, dict):
        print(f"[ERROR] '{path}' is corrupted (root must be a JSON object).")
        raise ValueError(f"'{path}' is corrupted: expected a dict")
    
    return users_dict


    


