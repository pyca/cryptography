import re

from text_validator.base import Plugin


class Characters(Plugin):
    def validate_line(self, filename, line_num, line):
        def error(message, offset=None):
            self.error_callback(filename, line_num, offset, message)

        encoding = self.config.get("ENCODING", "utf-8")
        decoded_line = line.decode(encoding)

        for i, char in enumerate(decoded_line, 1):
            for bad_char, suggested_char in self.config.get("REPLACE_CHARS", []):
                if char == bad_char:
                    error(
                        f"bad U+{ord(bad_char):04X};"
                        f"consider replacing with U+{ord(suggested_char):04X}",
                        i,
                    )

        token_separator = r"\s+"
        if "TOKEN_REGEXES" in self.config:
            i = 0
            for token in re.split(f"({token_separator})", decoded_line):
                if token and not re.match(f"{token_separator}$", token):
                    match = False
                    for regex in self.config["TOKEN_REGEXES"]:
                        if re.match(regex, token):
                            match = True
                            break
                    if not match:
                        token_hex = " ".join(f"U+{ord(ch):04X}" for ch in token)
                        error(
                            f"token {token} [{token_hex}] did not match any TOKEN_REGEXES",
                            i,
                        )
                i += len(token)


plugin = Characters
