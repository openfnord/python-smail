# _*_ coding: utf-8 _*_
import subprocess


def get_cmd_output(args):
    try:
        result = subprocess.check_output(args, stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError as err:
        raise Exception("Running shell command \"{}\" caused "
                        "error: {} (RC: {})".format(err.cmd, err.output, err.returncode))

    except Exception as err:
        raise Exception("Error: {}".format(err))

    return result.decode()
