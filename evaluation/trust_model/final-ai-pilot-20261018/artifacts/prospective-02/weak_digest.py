import hashlib
def password_digest(value):
    return hashlib.md5(value.encode()).hexdigest()
