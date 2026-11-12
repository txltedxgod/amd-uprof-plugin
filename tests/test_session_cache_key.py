"""The session cache must not change the search identity its own entries are keyed by.

Run from the repository root: python tests/run_tests.py test_session_cache_key
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import uprof_cache


class SessionCacheInsideSymbolCacheTest(unittest.TestCase):
    """The default session cache root lies inside the default srv* symbol cache."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="uprof-srv-")
        self.addCleanup(self.tmp.cleanup)
        self.srv = Path(os.path.realpath(self.tmp.name)) / "Symbols"
        self.srv.mkdir()

    def identity(self, cache_root):
        with mock.patch.dict(os.environ, {
                "_NT_SYMBOL_PATH": f"srv*{self.srv}*https://example.invalid",
                "UPROF_SESSION_CACHE_ROOT": str(cache_root)}):
            return uprof_cache.search_identity(None, None, [])["srv_caches"]

    def assert_storing_keeps_the_identity(self, cache_root):
        cache_root.mkdir(exist_ok=True)
        before = self.identity(cache_root)
        (cache_root / ("0" * 32 + ".duckdb")).write_bytes(b"cache")
        (cache_root / ("0" * 32 + ".duckdb.wal")).write_bytes(b"wal")
        self.assertEqual(self.identity(cache_root), before)

    def test_a_session_cache_below_the_srv_cache_is_not_fingerprinted(self):
        self.assert_storing_keeps_the_identity(self.srv / "uprof-session-cache")

    def test_a_session_cache_at_the_srv_cache_root_is_not_fingerprinted(self):
        self.assert_storing_keeps_the_identity(self.srv)

    def test_a_staged_pdb_still_changes_the_identity(self):
        cache_root = self.srv / "uprof-session-cache"
        cache_root.mkdir()
        before = self.identity(cache_root)
        (self.srv / "a.pdb" / "GUIDAGE").mkdir(parents=True)
        self.assertNotEqual(self.identity(cache_root), before)


if __name__ == "__main__":
    unittest.main()
