
import json
import os
import tempfile
import unittest

from server.auth import create_user_record, verify_user, load_users


class TestAuth(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, text):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_record_format(self):
        record = create_user_record("123456")
        self.assertEqual(set(record), {"salt", "hash"})
        self.assertEqual(len(record["salt"]), 32)   
        self.assertEqual(len(record["hash"]), 64)   

    def test_same_password_different_salt(self):
        r1 = create_user_record("123456")
        r2 = create_user_record("123456")
        self.assertNotEqual(r1["salt"], r2["salt"])
        self.assertNotEqual(r1["hash"], r2["hash"])

    def test_verify(self):
        users = {"tri": create_user_record("123456")}
        self.assertTrue(verify_user(users, "tri", "123456"))
        self.assertFalse(verify_user(users, "tri", "wrong"))
        self.assertFalse(verify_user(users, "nobody", "123456"))

    def test_load_round_trip(self):
        users = {"tri": create_user_record("123456")}
        path = self._write("ok.json", json.dumps(users))
        loaded = load_users(path)
        self.assertTrue(verify_user(loaded, "tri", "123456"))

    def test_load_missing_file(self):
        self.assertEqual(load_users(os.path.join(self.tmp.name, "none.json")), {})

    def test_load_broken_json(self):
        path = self._write("broken.json", '{"tri": {"salt": "abc"')
        with self.assertRaises(ValueError):
            load_users(path)

    def test_load_not_an_object(self):
        path = self._write("list.json", "[]")
        with self.assertRaises(ValueError):
            load_users(path)

    def test_demo_accounts(self):
        users = load_users(os.path.join("server", "data", "users.json"))
        for name in ("tri_demo", "nam_demo", "an_demo", "binh_demo"):
            self.assertTrue(verify_user(users, name, "123456"), name)
            
if __name__ == "__main__":
    unittest.main()
