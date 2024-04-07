import subprocess

UNIX_NEWLINE = "\n"
WINDOWS_NEWLINE = "\r\n"
MAC_NEWLINE = "\r"


def normalize_line_endings(lines, line_ending="unix"):
    """Normalizes line endings to unix (\n), windows (\r\n) or mac (\r).

    Args:
        lines (str): The lines to normalize.
        line_ending (str): Acceptable values are 'unix' (default), 'windows' and 'mac'.

    Returns:
        str: Line endings normalized.

    """
    lines = lines.replace(WINDOWS_NEWLINE, UNIX_NEWLINE).replace(MAC_NEWLINE, UNIX_NEWLINE)
    if line_ending == "windows":
        lines = lines.replace(UNIX_NEWLINE, WINDOWS_NEWLINE)
    elif line_ending == "mac":
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
        raise Exception(f"Running shell command \"{err.cmd}\" caused error: {err.output} (RC: {err.returncode})")

    except Exception as err:
        raise Exception(f"Error: {err}")

    return result.decode()


HEADERS_TO_KEEP = ["Content-Type", "MIME-Version", "Content-Transfer-Encoding"]


def pop_headers(msg):
    headers = {}
    # besides some special ones (e.g. Content-Type) remove all headers before encrypting the body content
    for hdr_name in msg.keys():
        if hdr_name.lower() in (h.lower() for h in HEADERS_TO_KEEP):
            continue

        values = msg.get_all(hdr_name)
        if values:
            del msg[hdr_name]
            headers[hdr_name] = values

    return headers
