# Utilities

import subprocess

UNIX_NEWLINE = '\n'
WINDOWS_NEWLINE = '\r\n'
MAC_NEWLINE = '\r'


def append_lines(lines, wrap, buf):
    """Append lines to the buffer. If the first line can be appended to the last
    line of the buf without exceeding wrap characters, the two lines are merged.
    Args:
        lines: an iterable of lines to append
        wrap:  maximum number of characters per line. 0 or negative wrap means
               no limit.
        buf:   an iterable of lines to append to"""
    if not lines:
        return
    if not buf or 0 < wrap < len(buf[-1]) + len(lines[0]):
        buf += lines
    else:
        buf[-1] += lines[0]
        buf += lines[1:]


def wrap_lines(long_string, wrap):
    """Split the long string into line chunks according to the wrap limit and
    existing newlines.
    Args:
        long_string: a long, possibly multiline string
        wrap:        maximum number of characters per line. 0 or negative
                     wrap means no limit.
    Returns:
       a list of lines of at most |wrap| characters each."""
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
    r"""Normalize line endings to unix (\n), windows (\r\n) or mac (\r).
    :param lines: The lines to normalize.
    :param line_ending: The line ending format.
    Acceptable values are 'unix' (default), 'windows' and 'mac'.
    :return: Line endings normalized.
    """
    lines = lines.replace(WINDOWS_NEWLINE, UNIX_NEWLINE).replace(MAC_NEWLINE, UNIX_NEWLINE)
    if line_ending == 'windows':
        lines = lines.replace(UNIX_NEWLINE, WINDOWS_NEWLINE)
    elif line_ending == 'mac':
        lines = lines.replace(UNIX_NEWLINE, MAC_NEWLINE)
    return lines


def get_cmd_output(args):
    try:
        result = subprocess.check_output(args, stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError as err:
        raise Exception("Running shell command \"{}\" caused "
                        "error: {} (RC: {})".format(err.cmd, err.output, err.returncode))

    except Exception as err:
        raise Exception("Error: {}".format(err))

    return result.decode()
