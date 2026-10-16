import hashlib
def case_0_0(password):
    return hashlib.md5(password.encode()).hexdigest()
