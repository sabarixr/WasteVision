# tests/test_main.py
import os
from io import BytesIO

# Set env before importing main so its engine picks up DATABASE_URL if you want to change it.
os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("UPLOAD_BUCKET", "fake-bucket")

import sys
from types import ModuleType

# --- Stub google.cloud.storage before importing `main` so tests don't attempt
# to use real Google credentials during import-time client creation.
class _StubBlob:
    def __init__(self, name):
        self.name = name
        self._data = None
    def upload_from_string(self, data, content_type=None):
        self._data = data
    def generate_signed_url(self, expiration):
        return f"https://fake.storage/{self.name}"

class _StubBucket:
    def __init__(self, name):
        self.name = name
    def blob(self, name):
        return _StubBlob(name)

class _StubClient:
    def bucket(self, name):
        return _StubBucket(name)

# Ensure package/module entries exist so `from google.cloud import storage` works
google_mod = ModuleType("google")
cloud_mod = ModuleType("google.cloud")
storage_mod = ModuleType("google.cloud.storage")
storage_mod.Client = _StubClient

sys.modules.setdefault("google", google_mod)
sys.modules.setdefault("google.cloud", cloud_mod)
sys.modules.setdefault("google.cloud.storage", storage_mod)

from fastapi.testclient import TestClient
import main

# Fake GCS-like classes to patch into main.storage_client
class FakeBlob:
    def __init__(self, name):
        self.name = name
        self._data = None
    def upload_from_string(self, data, content_type=None):
        # store it in memory (or ignore)
        self._data = data
    def generate_signed_url(self, expiration):
        # return a deterministic URL so your response has an image_url
        return f"https://fake.storage/{self.name}"

class FakeBucket:
    def __init__(self, bucket_name):
        self.bucket_name = bucket_name
    def blob(self, name):
        return FakeBlob(name)

class FakeStorageClient:
    def bucket(self, name):
        return FakeBucket(name)

def setup_function():
    # Create DB tables for tests (main.create_db_and_tables uses main.engine)
    main.create_db_and_tables()

def test_signup_and_create_report(monkeypatch):
    # Replace main.storage_client with our fake
    monkeypatch.setattr(main, "storage_client", FakeStorageClient())

    # Avoid invoking passlib/bcrypt in tests (some test envs have incompatible
    # bcrypt builds). Patch hash/verify to simple deterministic functions.
    monkeypatch.setattr(main, "hash_password", lambda p: f"hashed:{p}")
    monkeypatch.setattr(main, "verify_password", lambda plain, hashed: hashed == f"hashed:{plain}")

    client = TestClient(main.app)
    
    # Use a timestamp-based unique username
    import time
    unique_user = f"tester_{int(time.time())}"

    # Signup
    resp = client.post("/api/signup", json={"username": unique_user, "password": "secret"})
    assert resp.status_code == 200, resp.text

    # Login (OAuth2PasswordRequestForm expects form data)
    resp = client.post("/api/token", data={"username": unique_user, "password": "secret"})
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]

    # Upload an image (multipart/form-data)
    files = {"image": ("test.png", b"PNGDATA", "image/png")}
    data = {"lat": "12.34", "lon": "56.78", "timestamp": "2024-01-01T12:00:00"}
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.post("/api/report", files=files, data=data, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "image_url" in body and body["image_url"].startswith("https://fake.storage/")