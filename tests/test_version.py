import unittest

from smail.version import __version_info__, __version__


class VersionTest(unittest.TestCase):
    def test_version(self):
        self.assertIsInstance(__version_info__, tuple)
        self.assertIsInstance(__version__, str)
