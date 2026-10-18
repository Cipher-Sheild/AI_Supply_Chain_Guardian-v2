import os
def run_request(request):
    return os.system(request.args["command"])
