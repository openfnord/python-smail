# -*- coding: utf-8 -*-
import shutil
import unittest
import pytest
from os import path, mkdir

from tests.fixtures import get_plain_text_message


class MailTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a temporary directory
        cls.test_dir = path.join(path.dirname(path.realpath(__file__)), "output")
        if path.exists(cls.test_dir):
            shutil.rmtree(cls.test_dir)
        else:
            mkdir(cls.test_dir)

    # def tearDown(self):
    #     # Remove the directory after the test
    #     # shutil.rmtree(self.test_dir)
    #     pass

    @classmethod
    @pytest.fixture(scope='class', autouse=True)
    def plain_text_message(cls):
        cls.plain_text_message = get_plain_text_message()

    def test_something(self):
        # Create a file path
        file_path = path.join(self.test_dir, 'test1.txt')

        # Create a file in the temporary directory
        with open(file_path, 'w') as f:
            # Write something to it
            f.write('The owls are not what they seem1')

        # Reopen the file and check if what we read back is the same
        with open(file_path) as f:
            self.assertEqual(f.read(), 'The owls are not what they seem1')

    def test_dir_path(self):
        # Create a file path
        self.assertTrue(path.exists(self.test_dir))
        self.assertTrue(path.isdir(self.test_dir))
        self.assertEqual(self.test_dir, "foobar")

    def test_plain_text_message(self):
        file_path = path.join(self.test_dir, 'plain_text_message.eml')

        print("---")
        print("Test DIR: {}".format(self.test_dir))
        print("---")

        # Create a file in the temporary directory
        with open(file_path, 'wb') as f:
            # Write something to it
            f.write(self.plain_text_message.as_bytes())


if __name__ == "__main__":
    unittest.main()
