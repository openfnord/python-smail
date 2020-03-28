# -*- coding: utf-8 -*-
import unittest

from smail import utils


class PrintUtilTest(unittest.TestCase):
    def test_wrap_lines(self):
        long_multiline_string = "hello\nworld"
        self.assertEqual(["hel", "lo", "wor", "ld"],
                         utils.wrap_lines(long_multiline_string, 3))

    def test_wrap_lines_no_wrap(self):
        long_multiline_string = "hello\nworld"
        self.assertEqual(["hello", "world"],
                         utils.wrap_lines(long_multiline_string, 0))


if __name__ == "__main__":
    unittest.main()
