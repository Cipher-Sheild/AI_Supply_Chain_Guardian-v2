import requests
def case_1_0():
    return requests.get("https://example.org/item/0", verify=False)
