# -*- coding: utf-8 -*-
import unittest

from smail import utils


class TestUtils(unittest.TestCase):
    def test_normalize_line_endings(self):
        string = "hello world"
        self.assertEqual("hello world",
                         utils.normalize_line_endings(string))


if __name__ == "__main__":
    unittest.main()
