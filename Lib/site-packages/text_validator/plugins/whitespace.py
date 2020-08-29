from text_validator.base import Plugin


class Whitespace(Plugin):
    def validate_line(self, filename, line_num, line):
        def error(message, offset=None):
            self.error_callback(filename, line_num, offset, message)

        encoding = self.config.get("ENCODING", "utf-8")
        decoded_line = line.decode(encoding)

        if self.config.get("CHECK_CRLF"):
            if decoded_line.endswith("\r\n"):
                error("line ends with CRLF")

        if self.config.get("CHECK_TABS"):
            if "\t" in decoded_line:
                error("line contains a tab", decoded_line.find("\t"))

        if self.config.get("CHECK_TRAILING_WHITESPACE"):
            if decoded_line.rstrip("\n").endswith((" ", "\t")):
                error("trailing whitespace")

    def validate_last_line(self, filename, line_num, line):
        def error(message, offset=None):
            self.error_callback(filename, line_num, offset, message)

        encoding = self.config.get("ENCODING", "utf-8")
        decoded_line = line.decode(encoding)

        if self.config.get("CHECK_NO_EOF_NEWLINE"):
            if not decoded_line.endswith("\n"):
                error("no newline at end of file")


plugin = Whitespace
