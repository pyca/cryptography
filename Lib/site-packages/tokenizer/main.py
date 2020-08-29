#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""

    Tokenizer for Icelandic text

    Copyright (C) 2020 Miðeind ehf.
    Original author: Vilhjálmur Þorsteinsson

    This software is licensed under the MIT License:

        Permission is hereby granted, free of charge, to any person
        obtaining a copy of this software and associated documentation
        files (the "Software"), to deal in the Software without restriction,
        including without limitation the rights to use, copy, modify, merge,
        publish, distribute, sublicense, and/or sell copies of the Software,
        and to permit persons to whom the Software is furnished to do so,
        subject to the following conditions:

        The above copyright notice and this permission notice shall be
        included in all copies or substantial portions of the Software.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
        IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
        CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
        TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
        SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


    This is an executable program wrapper (main module) for the Tokenizer
    package. It can be used to invoke the Tokenizer from the command line,
    or via fork() or exec(), with the command 'tokenize'. The main() function
    of this module is registered as a console_script entry point in setup.py.

"""

from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

import sys
import argparse
import json
from functools import partial

from .tokenizer import TOK, tokenize
from .definitions import make_str


if sys.version_info >= (3, 0):
    # Python 3: read and write strings from and to UTF-8 encoded files
    ReadFile = argparse.FileType('r', encoding="utf-8")
    WriteFile = argparse.FileType('w', encoding="utf-8")
else:
    # Python 2: read and write bytes, which are decoded from UTF-8 in the gen() function
    ReadFile = argparse.FileType('r')
    WriteFile = argparse.FileType('w')

# Define the command line arguments

parser = argparse.ArgumentParser(description="Tokenizes Icelandic text")

parser.add_argument(
    'infile',
    nargs='?',
    type=ReadFile,
    default=sys.stdin,
    help="UTF-8 text file to tokenize",
)
parser.add_argument(
    'outfile',
    nargs='?',
    type=WriteFile,
    default=sys.stdout,
    help="UTF-8 output text file"
)

group = parser.add_mutually_exclusive_group()
group.add_argument(
    "--csv",
    help="Output one token per line in CSV format", action="store_true"
)
group.add_argument(
    "--json",
    help="Output one token per line in JSON format", action="store_true"
)
group.add_argument(
    "--normalize",
    help="Normalize punctuation", action="store_true"
)


def main():
    """ Main function, called when the tokenize command is invoked """

    args = parser.parse_args()
    options = dict()

    def quote(s):
        """ Return the string s within double quotes, and with any contained
            backslashes and double quotes escaped with a backslash """
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

    def gen(f):
        """ Generate the lines of text in the input file """
        for line in f:
            yield make_str(line)

    def val(t, quote_word=False):
        """ Return the value part of the token t """
        if t.val is None:
            return None
        if t.kind == TOK.WORD:
            # Get the full expansion of an abbreviation
            if quote_word:
                # Return a |-delimited list of possible meanings,
                # joined into a single string
                return quote("|".join(m[0] for m in t.val))
            # Return a list of all possible meanings
            return [m[0] for m in t.val]
        if t.kind in {TOK.PERCENT, TOK.NUMBER, TOK.CURRENCY}:
            return t.val[0]
        if t.kind == TOK.AMOUNT:
            if quote_word:
                # Format as "1234.56|USD"
                return "\"{0}|{1}\"".format(t.val[0], t.val[1])
            return t.val[0], t.val[1]
        if t.kind == TOK.S_BEGIN:
            return None
        if t.kind == TOK.PUNCTUATION:
            return quote(t.val[1]) if quote_word else t.val[1]
        if quote_word and t.kind in {
            TOK.DATE, TOK.TIME, TOK.DATEABS, TOK.DATEREL, TOK.TIMESTAMP,
            TOK.TIMESTAMPABS, TOK.TIMESTAMPREL, TOK.TELNO, TOK.NUMWLETTER,
            TOK.MEASUREMENT
        }:
            # Return a |-delimited list of numbers
            return quote("|".join(str(v) for v in t.val))
        if quote_word and isinstance(t.val, str):
            return quote(t.val)
        return t.val

    if args.normalize:
        to_text = lambda t: (t.val[1] if t.kind == TOK.PUNCTUATION else t.txt)
    else:
        to_text = lambda t: t.txt

    # Configure our JSON dump function
    json_dumps = partial(json.dumps, ensure_ascii=False, separators=(',', ':'))
    curr_sent = []

    for t in tokenize(gen(args.infile), **options):
        if args.csv:
            # Output the tokens in CSV format, one line per token
            if t.txt:
                print(
                    "{0},{1},{2}"
                    .format(t.kind, quote(t.txt), val(t, quote_word=True) or "\"\""),
                    file=args.outfile
                )
            elif t.kind == TOK.S_END:
                # Indicate end of sentence
                print("0,\"\",\"\"", file=args.outfile)
        elif args.json:
            # Output the tokens in JSON format, one line per token
            d = dict(k=TOK.descr[t.kind])
            if t.txt is not None:
                d["t"] = t.txt
            v = val(t)
            if v is not None:
                d["v"] = v
            print(json_dumps(d), file=args.outfile)
        else:
            # Normal shallow parse, one line per sentence,
            # tokens separated by spaces
            if t.kind in TOK.END:
                # End of sentence/paragraph
                if curr_sent:
                    print(" ".join(curr_sent), file=args.outfile)
                    curr_sent = []
            else:
                txt = to_text(t)
                if txt:
                    curr_sent.append(txt)

    if curr_sent:
        print(" ".join(curr_sent), file=args.outfile)


if __name__ == "__main__":
    main()
