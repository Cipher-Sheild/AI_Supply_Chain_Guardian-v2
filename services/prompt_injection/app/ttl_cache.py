import time
import threading
from collections import OrderedDict
class TTLCache:
    def __init__(self, max_entries=512, ttl=3600):
        self.max_entries, self.ttl = max_entries, ttl
        self.entries = OrderedDict()
        self.lock = threading.Lock()
    def get(self, key):
        with self.lock:
            entry = self.entries.get(key)
            if entry is None: return None
            deadline, value = entry
            if time.monotonic() >= deadline:
                self.entries.pop(key, None)
                return None
            self.entries.move_to_end(key)
            return value
    def set(self, key, value, ttl=None):
        # Never persist transport/registry failures as clean observations.
        if isinstance(value, dict) and (value.get("status", 200) in {"error", "timeout"} or isinstance(value.get("status"), int) and value["status"] >= 500): return
        with self.lock:
            self.entries[key] = (time.monotonic() + (self.ttl if ttl is None else ttl), value)
            self.entries.move_to_end(key)
            while len(self.entries) > self.max_entries: self.entries.popitem(last=False)
    def clear(self):
        with self.lock: self.entries.clear()
