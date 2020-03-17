# -*- coding: utf-8 -*-
import shutil
import unittest
import pytest
import os

from tests.fixtures import get_plain_text_message


class MailTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # use tests/output/ as target for output files
        cls.test_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "output")
        if not os.path.exists(cls.test_dir):
            os.mkdir(cls.test_dir)
        else:
            # directory exists - remove all files in it
            for file_object in os.listdir(cls.test_dir):
                file_object_path = os.path.join(cls.test_dir, file_object)
                if os.path.isfile(file_object_path) or os.path.islink(file_object_path):
                    os.unlink(file_object_path)
                else:
                    shutil.rmtree(file_object_path)

    # def tearDown(self):
    #     # Remove the directory after the test
    #     # shutil.rmtree(self.test_dir)
    #     pass

    @classmethod
    @pytest.fixture(scope='class', autouse=True)
    def plain_text_message(cls):
        cls.plain_text_message = get_plain_text_message()

    # def test_something(self):
    #     # Create a file path
    #     file_path = os.path.join(self.test_dir, 'test1.txt')
    #
    #     # Create a file in the temporary directory
    #     with open(file_path, 'w') as f:
    #         # Write something to it
    #         f.write('The owls are not what they seem1')
    #
    #     # Reopen the file and check if what we read back is the same
    #     with open(file_path) as f:
    #         self.assertEqual(f.read(), 'The owls are not what they seem1')

    # def test_dir_path(self):
    #     # Create a file path
    #     self.assertEqual(self.test_dir, "foobar")

    def test_plain_text_message(self):
        file_path = os.path.join(self.test_dir, 'plain_text_message.eml')

        # Create a file in the temporary directory
        with open(file_path, 'wb') as f:
            # Write something to it
            f.write(self.plain_text_message.as_bytes())


if __name__ == "__main__":
    unittest.main()
