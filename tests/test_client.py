"""Unit tests for the client core's file reassembly (no server needed)."""

import base64
import hashlib
import os
import tempfile
import unittest

from client.client import ChatClient


def file_messages(data, chunk_size=1000, file_id="f1"):
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
    meta = {"type": "FILE_META", "from": "tri_demo", "file_id": file_id, "name": "a.bin",
            "size": len(data), "chunks": len(chunks), "sha256": hashlib.sha256(data).hexdigest()}
    parts = [{"type": "FILE_CHUNK", "from": "tri_demo", "file_id": file_id, "index": i,
              "data": base64.b64encode(c).decode()} for i, c in enumerate(chunks)]
    end = {"type": "FILE_END", "from": "tri_demo", "file_id": file_id}
    return meta, parts, end


class TestFileReassembly(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.folder = tempfile.mkdtemp()
        self.client = ChatClient(on_event=self.events.append, download_dir=self.folder)
        self.client.username = "nam_demo"

    def done_event(self):
        return [e for e in self.events if e["type"] == "file_done"][-1]

    def test_file_is_saved_and_checked(self):
        data = os.urandom(5500)
        meta, parts, end = file_messages(data)
        for m in [meta] + parts + [end]:
            self.client._handle(m)
        done = self.done_event()
        self.assertTrue(done["ok"])
        with open(done["path"], "rb") as f:
            self.assertEqual(f.read(), data)

    def test_chunks_in_any_order_and_duplicates(self):
        data = os.urandom(5500)
        meta, parts, end = file_messages(data)
        for m in [meta] + parts[::-1] + parts[:2] + [end]:
            self.client._handle(m)
        self.assertTrue(self.done_event()["ok"])

    def test_corrupted_chunk_is_detected(self):
        data = os.urandom(3000)
        meta, parts, end = file_messages(data)
        parts[1]["data"] = base64.b64encode(b"x" * 1000).decode()
        for m in [meta] + parts + [end]:
            self.client._handle(m)
        done = self.done_event()
        self.assertFalse(done["ok"])
        self.assertIn("SHA-256", done["reason"])

    def test_missing_chunk_is_detected(self):
        meta, parts, end = file_messages(os.urandom(3000))
        for m in [meta] + parts[:-1] + [end]:
            self.client._handle(m)
        self.assertIn("missing", self.done_event()["reason"])

    def test_same_name_is_not_overwritten(self):
        for file_id in ("f1", "f2"):
            meta, parts, end = file_messages(b"abc", file_id=file_id)
            for m in [meta] + parts + [end]:
                self.client._handle(m)
        self.assertEqual(sorted(os.listdir(os.path.join(self.folder, "nam_demo"))), ["a (1).bin", "a.bin"])


if __name__ == "__main__":
    unittest.main()
