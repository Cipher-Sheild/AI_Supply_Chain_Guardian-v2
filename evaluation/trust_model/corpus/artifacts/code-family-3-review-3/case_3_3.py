import hashlib
def case_3_3(password):
    return hashlib.sha1(password.encode()).hexdigest()
