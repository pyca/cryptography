'''tldextract CLI'''


import logging
import sys

from .tldextract import TLDExtract
from ._version import version as __version__

try:
    unicode
except NameError:
    unicode = str  # pylint: disable=invalid-name,redefined-builtin


def main():
    '''tldextract CLI main command.'''
    import argparse

    logging.basicConfig()

    parser = argparse.ArgumentParser(
        prog='tldextract',
        description='Parse hostname from a url or fqdn')

    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('input', metavar='fqdn|url',
                        type=unicode, nargs='*', help='fqdn or url')

    parser.add_argument('-u', '--update', default=False, action='store_true',
                        help='force fetch the latest TLD definitions')
    parser.add_argument('-c', '--cache_file',
                        help='use an alternate TLD definition file')
    parser.add_argument('-p', '--private_domains', default=False, action='store_true',
                        help='Include private domains')

    args = parser.parse_args()
    tld_extract = TLDExtract(include_psl_private_domains=args.private_domains)

    if args.cache_file:
        tld_extract.cache_file = args.cache_file

    if args.update:
        tld_extract.update(True)
    elif not args.input:
        parser.print_usage()
        sys.exit(1)
        return

    for i in args.input:
        print(' '.join(tld_extract(i)))  # pylint: disable=superfluous-parens
