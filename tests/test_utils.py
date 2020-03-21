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

    def test_append_lines_appends(self):
        buf = ["hello"]
        lines = ["beautiful", "world"]
        # "hellobeautiful" is more than 10 characters long
        utils.append_lines(lines, 20, buf)
        self.assertEqual(["hellobeautiful", "world"], buf)

    def test_append_lines_honours_wrap(self):
        buf = ["hello"]
        lines = ["beautiful", "world"]
        # "hellobeautiful" is more than 10 characters long
        utils.append_lines(lines, 10, buf)
        self.assertEqual(["hello", "beautiful", "world"], buf)


if __name__ == "__main__":
    unittest.main()
