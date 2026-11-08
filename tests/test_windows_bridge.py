import unittest
from unittest.mock import patch

from jarvis_origin import collect_windows


class BridgeTests(unittest.TestCase):
    def test_cached_path_on_unreadable_mount_is_not_available(self):
        with patch.object(collect_windows, '_PS', '/missing/powershell.exe'), \
             patch.object(collect_windows.os.path, 'isfile', return_value=False), \
             patch.object(collect_windows, 'ensure_interop', return_value=True):
            self.assertFalse(collect_windows.available())

    def test_readable_binary_still_requires_interop(self):
        with patch.object(collect_windows, '_PS', '/windows/powershell.exe'), \
             patch.object(collect_windows.os.path, 'isfile', return_value=True), \
             patch.object(collect_windows, 'ensure_interop', return_value=False):
            self.assertFalse(collect_windows.available())
