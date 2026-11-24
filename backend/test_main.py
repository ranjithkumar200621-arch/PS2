import os
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from fastapi import HTTPException
from main import app, public_url

class Tests(unittest.TestCase):
    def test_strip_private_url_parts(self):
        self.assertEqual(public_url("https://example.com/path?otp=123#secret"), "https://example.com/path")
    def test_reject_local_or_credentials(self):
        for value in ["file:///etc/passwd", "http://127.0.0.1", "https://user:pass@example.com", "http://host.local", "http://169.254.169.254"]:
            with self.subTest(value=value), self.assertRaises(HTTPException): public_url(value)
    def test_no_credentials_no_access(self):
        with patch.dict(os.environ, {"PS2_API_TOKEN": "test"}):
            self.assertEqual(TestClient(app).post('/verify', json={"kind":"claim","query":"test"}).status_code, 401)
    def test_missing_provider_is_unverified(self):
        with patch.dict(os.environ, {"PS2_API_TOKEN": "test", "FACT_CHECK_API_KEY": ""}):
            r = TestClient(app).post('/verify', headers={"Authorization":"Bearer test"}, json={"kind":"claim","query":"test"})
            self.assertEqual(r.json()["verdict"], "Unverified")
    def test_bound_input(self):
        self.assertEqual(TestClient(app).post('/verify', json={"kind":"claim","query":"a"*2001}).status_code, 422)

if __name__ == '__main__': unittest.main()
