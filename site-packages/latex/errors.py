import re

LATEX_ERR_RE = re.compile(r'(?P<filename>([a-zA-Z]:)?[^:]+):(?P<line>[0-9]+):'
                          r'\s*(?P<error>.*)')


def parse_log(log, context_size=3):
    """Parses latex log output and tries to extract error messages.

    Requires ``-file-line-error`` to be active.

    :param log: The contents of the logfile as a string.
    :param context_size: Number of lines to keep as context, including the
                         original error line.
    :return: A dictionary containig ``line`` (line number, an int), ``error``,
             (the error message), ``filename`` (name of the temporary file
             used for building) and ``context`` (list of lines, starting with
             with the error line).
    """
    lines = log.splitlines()
    errors = []

    for n, line in enumerate(lines):
        m = LATEX_ERR_RE.match(line)
        if m:
            err = m.groupdict().copy()
            err['context'] = lines[n:n + context_size]
            try:
                err['line'] = int(err['line'])
            except TypeError:
                pass  # ignore invalid int conversion
            errors.append(err)

    return errors
