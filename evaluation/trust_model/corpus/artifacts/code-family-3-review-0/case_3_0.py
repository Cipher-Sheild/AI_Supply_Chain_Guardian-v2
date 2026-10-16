import hashlib
def case_3_0(password):
    return hashlib.sha1(password.encode()).hexdigest()
