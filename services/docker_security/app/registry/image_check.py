import time
import urllib.request
import urllib.error
import re
from urllib.parse import quote
from app.schema import Finding
from app.engines.result import EngineResult
from app.registry.image_reference import ImageReference
from app.cache import cache_instance

BLOCKED_HOST_PATTERNS = re.compile(r"(?i)^(localhost|127\.|169\.254|10\.|172\.(1[6-9]|2[0-9]|3[01])|192\.168|0\.0\.0\.0)")

class BaseImageChecker:
    def __init__(self, timeout_sec=3.0): self.timeout_sec = timeout_sec

    def is_safe_image_ref(self, base_image, tag):
        try:
            ref = ImageReference.parse(base_image + (":" + tag if tag else ""))
            return not BLOCKED_HOST_PATTERNS.search(ref.repository)
        except ValueError: return False

    def check_image_exists(self, base_image, tag="latest", line_number=1, file_path="Dockerfile"):
        reference = base_image if "@" in base_image else base_image + (":" + tag if tag else "")
        started = time.perf_counter()
        def result(completed, error=None, findings=None):
            return EngineResult(completed, error, (time.perf_counter()-started)*1000, findings or [])
        def blocked(reason, category):
            return result(True, findings=[Finding(detector_id="DSG-D012",file_path=file_path,
                line_number=line_number, preview=reference,confidence=1,severity="critical",reason=reason,
                remediation="Verify the image repository and reference.",sources=["registry:DSG-D012"],
                category=category,hard_block=True)])
        if base_image == "scratch": return result(True)
        if base_image.startswith("$"): return result(False, "unresolved build argument")
        try: ref = ImageReference.parse(reference)
        except ValueError: return blocked("Invalid image reference", "invalid_image_ref")
        if BLOCKED_HOST_PATTERNS.search(ref.repository): return blocked("Prohibited registry host", "invalid_image_ref")
        if ref.registry not in {"docker.io", "index.docker.io", "registry-1.docker.io"}:
            return result(False, "non-Docker-Hub registry unverified")
        if ref.digest: return result(False, "digest verification requires registry manifest API")
        repository = ref.repository
        if repository.startswith(ref.registry + "/"): repository = repository[len(ref.registry)+1:]
        if "/" not in repository: repository = "library/"+repository
        key = "img_exist:v1:"+reference
        cached = cache_instance.get(key)
        if cached is not None:
            return result(True) if cached["exists"] else blocked("Image does not exist (404)", "non_existent_image")
        url = "https://hub.docker.com/v2/repositories/"+quote(repository,safe="/")+"/tags/"+quote(ref.tag,safe="")
        try:
            with urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"Guardian/1.0"}),timeout=self.timeout_sec) as response:
                if response.status != 200: return result(False, "unexpected registry status")
            cache_instance.set(key,{"exists":True},ttl=86400)
            return result(True)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                cache_instance.set(key,{"exists":False},ttl=300)
                return blocked("Image does not exist (404)", "non_existent_image")
            return result(False,"registry HTTP "+str(exc.code))
        except Exception as exc: return result(False,type(exc).__name__)
