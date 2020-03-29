# Utilities

import subprocess

UNIX_NEWLINE = '\n'
WINDOWS_NEWLINE = '\r\n'
MAC_NEWLINE = '\r'


def wrap_lines(long_string, wrap):
    """Takes a string and returns a list of wrapped lines.

    Split the long string into line chunks according to the wrap limit and
    existing newlines.

    Args:
        long_string(str): a long, possibly multiline string
        wrap (int): maximum number of characters per line. 0 or negative wrap means no limit.

    Returns:
        :obj:`list` of :obj:`str`: list of lines of at most `wrap` characters each.

    """

    if not long_string:
        return []

    if isinstance(long_string, bytes):
        long_string = long_string.decode()

    long_lines = long_string.split("\n")
    if wrap <= 0:
        return long_lines

    ret = []
    for line in long_lines:
        if not line:
            # Empty line
            ret += [line]
        else:
            ret += [line[i: i + wrap] for i in range(0, len(line), wrap)]

    return ret


def normalize_line_endings(lines, line_ending='unix'):
    """Normalizes line endings to unix (\n), windows (\r\n) or mac (\r).

    Args:
        lines (str): The lines to normalize.
        line_ending (str): Acceptable values are 'unix' (default), 'windows' and 'mac'.

    Returns:
        str: Line endings normalized.

    """
    lines = lines.replace(WINDOWS_NEWLINE, UNIX_NEWLINE).replace(MAC_NEWLINE, UNIX_NEWLINE)
    if line_ending == 'windows':
        lines = lines.replace(UNIX_NEWLINE, WINDOWS_NEWLINE)
    elif line_ending == 'mac':
        lines = lines.replace(UNIX_NEWLINE, MAC_NEWLINE)

    return lines


def get_cmd_output(args):
    """Runs an OS command and returns the output.

    Args:
        args (:obj:`list` of :obj:`str`): Command to run and the arguments for it.

    Returns:
         str: The command line output.

    """

    try:
        result = subprocess.check_output(args, stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError as err:
        raise Exception("Running shell command \"{}\" caused "
                        "error: {} (RC: {})".format(err.cmd, err.output, err.returncode))

    except Exception as err:
        raise Exception("Error: {}".format(err))

    return result.decode()
