'tldextract helpers for testing and fetching remote resources.'


import logging
import re
import socket
import sys

import requests
from requests_file import FileAdapter

# pylint: disable=import-error,invalid-name,no-name-in-module,redefined-builtin
if sys.version_info < (3,):  # pragma: no cover
    from urlparse import scheme_chars
else:  # pragma: no cover
    from urllib.parse import scheme_chars
    unicode = str
# pylint: enable=import-error,invalid-name,no-name-in-module,redefined-builtin


IP_RE = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')  # pylint: disable=line-too-long

SCHEME_RE = re.compile(r'^([' + scheme_chars + ']+:)?//')

LOG = logging.getLogger('tldextract')


def find_first_response(urls, cache_fetch_timeout=None):
    """ Decode the first successfully fetched URL, from UTF-8 encoding to
    Python unicode.
    """
    with requests.Session() as session:
        session.mount('file://', FileAdapter())

        for url in urls:
            try:
                resp = session.get(url, timeout=cache_fetch_timeout)
                resp.raise_for_status()
            except requests.exceptions.RequestException:
                LOG.exception(
                    'Exception reading Public Suffix List url %s',
                    url
                )
            else:
                return _decode_utf8(resp.text)

    LOG.error(
        'No Public Suffix List found. Consider using a mirror or constructing '
        'your TLDExtract with `suffix_list_urls=None`.'
    )
    return unicode('')


def _decode_utf8(text):
    """ Decode from utf8 to Python unicode string.

    The suffix list, wherever its origin, should be UTF-8 encoded.
    """
    if not isinstance(text, unicode):
        return unicode(text, 'utf-8')
    return text


def looks_like_ip(maybe_ip):
    """Does the given str look like an IP address?"""
    if not maybe_ip[0].isdigit():
        return False

    try:
        socket.inet_aton(maybe_ip)
        return True
    except (AttributeError, UnicodeError):
        if IP_RE.match(maybe_ip):
            return True
    except socket.error:
        return False
