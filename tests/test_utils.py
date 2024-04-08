import os
import unittest

from smail import utils


class TestUtils(unittest.TestCase):
    def test_normalize_line_endings(self):
        string = "hello world"
        self.assertEqual("hello world", utils.normalize_line_endings(string))

    def test_normalize_line_endings2(self):
        if os.name == "nt":
            string = """hello
 Windows.

Bye"""
            self.assertEqual("hello\r\n Windows.\r\n\r\nBye",
                             utils.normalize_line_endings(string, line_ending="windows"))
        else:
            string = """hello
 Unix.

Bye"""
            self.assertEqual("hello\n Unix.\n\nBye", utils.normalize_line_endings(string))


if __name__ == "__main__":
    unittest.main()
