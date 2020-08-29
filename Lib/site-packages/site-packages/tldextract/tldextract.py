# -*- coding: utf-8 -*-
"""`tldextract` accurately separates the gTLD or ccTLD (generic or country code
top-level domain) from the registered domain and subdomains of a URL.

    >>> import tldextract

    >>> tldextract.extract('http://forums.news.cnn.com/')
    ExtractResult(subdomain='forums.news', domain='cnn', suffix='com')

    >>> tldextract.extract('http://forums.bbc.co.uk/') # United Kingdom
    ExtractResult(subdomain='forums', domain='bbc', suffix='co.uk')

    >>> tldextract.extract('http://www.worldbank.org.kg/') # Kyrgyzstan
    ExtractResult(subdomain='www', domain='worldbank', suffix='org.kg')

`ExtractResult` is a namedtuple, so it's simple to access the parts you want.

    >>> ext = tldextract.extract('http://forums.bbc.co.uk')
    >>> (ext.subdomain, ext.domain, ext.suffix)
    ('forums', 'bbc', 'co.uk')
    >>> # rejoin subdomain and domain
    >>> '.'.join(ext[:2])
    'forums.bbc'
    >>> # a common alias
    >>> ext.registered_domain
    'bbc.co.uk'

Note subdomain and suffix are _optional_. Not all URL-like inputs have a
subdomain or a valid suffix.

    >>> tldextract.extract('google.com')
    ExtractResult(subdomain='', domain='google', suffix='com')

    >>> tldextract.extract('google.notavalidsuffix')
    ExtractResult(subdomain='google', domain='notavalidsuffix', suffix='')

    >>> tldextract.extract('http://127.0.0.1:8080/deployed/')
    ExtractResult(subdomain='', domain='127.0.0.1', suffix='')

If you want to rejoin the whole namedtuple, regardless of whether a subdomain
or suffix were found:

    >>> ext = tldextract.extract('http://127.0.0.1:8080/deployed/')
    >>> # this has unwanted dots
    >>> '.'.join(ext)
    '.127.0.0.1.'
    >>> # join part only if truthy
    >>> '.'.join(part for part in ext if part)
    '127.0.0.1'
"""


import collections
import errno
from functools import wraps
import json
import logging
import os
import pkgutil
import re
import threading

import idna

from .remote import find_first_response
from .remote import looks_like_ip
from .remote import IP_RE
from .remote import SCHEME_RE

# pylint: disable=invalid-name,undefined-variable
try:
    STRING_TYPE = basestring
except NameError:
    STRING_TYPE = str
# pylint: enable=invalid-name,undefined-variable


LOG = logging.getLogger("tldextract")

CACHE_FILE_DEFAULT = os.path.join(os.path.dirname(__file__), '.tld_set')
CACHE_FILE = os.path.expanduser(os.environ.get("TLDEXTRACT_CACHE", CACHE_FILE_DEFAULT))
CACHE_TIMEOUT = os.environ.get('TLDEXTRACT_CACHE_TIMEOUT')

PUBLIC_SUFFIX_LIST_URLS = (
    'https://publicsuffix.org/list/public_suffix_list.dat',
    'https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat',
)

PUBLIC_SUFFIX_RE = re.compile(r'^(?P<suffix>[.*!]*\w[\S]*)', re.UNICODE | re.MULTILINE)


class ExtractResult(collections.namedtuple('ExtractResult', 'subdomain domain suffix')):
    '''namedtuple of a URL's subdomain, domain, and suffix.'''

    # Necessary for __dict__ member to get populated in Python 3+
    __slots__ = ()

    @property
    def registered_domain(self):
        """
        Joins the domain and suffix fields with a dot, if they're both set.

        >>> extract('http://forums.bbc.co.uk').registered_domain
        'bbc.co.uk'
        >>> extract('http://localhost:8080').registered_domain
        ''
        """
        if self.domain and self.suffix:
            return self.domain + '.' + self.suffix
        return ''

    @property
    def fqdn(self):
        """
        Returns a Fully Qualified Domain Name, if there is a proper domain/suffix.

        >>> extract('http://forums.bbc.co.uk/path/to/file').fqdn
        'forums.bbc.co.uk'
        >>> extract('http://localhost:8080').fqdn
        ''
        """
        if self.domain and self.suffix:
            # self is the namedtuple (subdomain domain suffix)
            return '.'.join(i for i in self if i)
        return ''

    @property
    def ipv4(self):
        """
        Returns the ipv4 if that is what the presented domain/url is

        >>> extract('http://127.0.0.1/path/to/file').ipv4
        '127.0.0.1'
        >>> extract('http://127.0.0.1.1/path/to/file').ipv4
        ''
        >>> extract('http://256.1.1.1').ipv4
        ''
        """
        if not (self.suffix or self.subdomain) and IP_RE.match(self.domain):
            return self.domain
        return ''


class TLDExtract(object):
    '''A callable for extracting, subdomain, domain, and suffix components from
    a URL.'''

    # TODO: Agreed with Pylint: too-many-arguments
    def __init__(self, cache_file=CACHE_FILE, suffix_list_urls=PUBLIC_SUFFIX_LIST_URLS,  # pylint: disable=too-many-arguments
                 fallback_to_snapshot=True, include_psl_private_domains=False, extra_suffixes=(),
                 cache_fetch_timeout=CACHE_TIMEOUT):
        """
        Constructs a callable for extracting subdomain, domain, and suffix
        components from a URL.

        Upon calling it, it first checks for a JSON `cache_file`.
        By default, the `cache_file` will live in the tldextract directory.

        You can disable the caching functionality of this module  by setting `cache_file` to False.

        If the `cache_file` does not exist (such as on the first run), HTTP request the URLs in
        `suffix_list_urls` in order, until one returns public suffix list data. To disable HTTP
        requests, set this to something falsy.

        The default list of URLs point to the latest version of the Mozilla Public Suffix List and
        its mirror, but any similar document could be specified. Local files can be specified by
        using the `file://` protocol. (See `urllib2` documentation.)

        If there is no `cache_file` loaded and no data is found from the `suffix_list_urls`,
        the module will fall back to the included TLD set snapshot. If you do not want
        this behavior, you may set `fallback_to_snapshot` to False, and an exception will be
        raised instead.

        The Public Suffix List includes a list of "private domains" as TLDs,
        such as blogspot.com. These do not fit `tldextract`'s definition of a
        suffix, so these domains are excluded by default. If you'd like them
        included instead, set `include_psl_private_domains` to True.

        You can pass additional suffixes in `extra_suffixes` argument without changing list URL

        cache_fetch_timeout is passed unmodified to the underlying request object
        per the requests documentation here:
        http://docs.python-requests.org/en/master/user/advanced/#timeouts

        cache_fetch_timeout can also be set to a single value with the
        environment variable TLDEXTRACT_CACHE_TIMEOUT, like so:

        TLDEXTRACT_CACHE_TIMEOUT="1.2"

        When set this way, the same timeout value will be used for both connect
        and read timeouts
        """
        suffix_list_urls = suffix_list_urls or ()
        self.suffix_list_urls = tuple(url.strip() for url in suffix_list_urls if url.strip())

        self.cache_file = os.path.expanduser(cache_file or '')
        self.cache_file_lock = threading.Lock()
        self.fallback_to_snapshot = fallback_to_snapshot
        if not (self.suffix_list_urls or self.cache_file or self.fallback_to_snapshot):
            raise ValueError("The arguments you have provided disable all ways for tldextract "
                             "to obtain data. Please provide a suffix list data, a cache_file, "
                             "or set `fallback_to_snapshot` to `True`.")

        self.include_psl_private_domains = include_psl_private_domains
        self.extra_suffixes = extra_suffixes
        self._extractor = None

        self.cache_fetch_timeout = cache_fetch_timeout
        if isinstance(self.cache_fetch_timeout, STRING_TYPE):
            self.cache_fetch_timeout = float(self.cache_fetch_timeout)

    def __call__(self, url):
        """
        Takes a string URL and splits it into its subdomain, domain, and
        suffix (effective TLD, gTLD, ccTLD, etc.) component.

        >>> extract = TLDExtract()
        >>> extract('http://forums.news.cnn.com/')
        ExtractResult(subdomain='forums.news', domain='cnn', suffix='com')
        >>> extract('http://forums.bbc.co.uk/')
        ExtractResult(subdomain='forums', domain='bbc', suffix='co.uk')
        """
        netloc = SCHEME_RE.sub("", url) \
            .partition("/")[0] \
            .partition("?")[0] \
            .partition("#")[0] \
            .split("@")[-1] \
            .partition(":")[0] \
            .strip() \
            .rstrip(".")

        labels = netloc.split(".")

        translations = [_decode_punycode(label) for label in labels]
        suffix_index = self._get_tld_extractor().suffix_index(translations)

        suffix = ".".join(labels[suffix_index:])
        if not suffix and netloc and looks_like_ip(netloc):
            return ExtractResult('', netloc, '')

        subdomain = ".".join(labels[:suffix_index - 1]) if suffix_index else ""
        domain = labels[suffix_index - 1] if suffix_index else ""
        return ExtractResult(subdomain, domain, suffix)

    def update(self, fetch_now=False):
        if os.path.exists(self.cache_file):
            os.unlink(self.cache_file)
        self._extractor = None
        if fetch_now:
            self._get_tld_extractor()

    @property
    def tlds(self):
        return self._get_tld_extractor().tlds

    def _get_tld_extractor(self):
        '''Get or compute this object's TLDExtractor. Looks up the TLDExtractor
        in roughly the following order, based on the settings passed to
        __init__:

        1. Memoized on `self`
        2. Local system cache file
        3. Remote PSL, over HTTP
        4. Bundled PSL snapshot file'''
        # pylint: disable=no-else-return

        if self._extractor:
            return self._extractor
        with self.cache_file_lock:
            tlds = self._get_cached_tlds()
        if tlds:
            tlds.extend(self.extra_suffixes)
            self._extractor = _PublicSuffixListTLDExtractor(tlds)
            return self._extractor
        elif self.suffix_list_urls:
            raw_suffix_list_data = find_first_response(
                self.suffix_list_urls,
                self.cache_fetch_timeout
            )
            tlds = get_tlds_from_raw_suffix_list_data(
                raw_suffix_list_data,
                self.include_psl_private_domains
            )

        if not tlds and self.fallback_to_snapshot:
            tlds = self._get_snapshot_tld_extractor()
            tlds.extend(self.extra_suffixes)
            self._extractor = _PublicSuffixListTLDExtractor(tlds)
            return self._extractor
        elif not tlds:
            raise Exception("tlds is empty, but fallback_to_snapshot is set"
                            " to false. Cannot proceed without tlds.")

        with self.cache_file_lock:
            self._cache_tlds(tlds)

        tlds.extend(self.extra_suffixes)
        self._extractor = _PublicSuffixListTLDExtractor(tlds)
        return self._extractor

    def _get_cached_tlds(self):
        '''Read the local TLD cache file. Returns None on IOError or other
        error, or if this object is not set to use the cache
        file.'''
        if not self.cache_file:
            return None

        try:
            with open(self.cache_file) as cache_file:
                try:
                    return json.loads(cache_file.read())
                except (IOError, ValueError) as exc:
                    LOG.error(
                        "error reading TLD cache file %s: %s",
                        self.cache_file,
                        exc
                    )
        except IOError as ioe:
            file_not_found = ioe.errno == errno.ENOENT
            if not file_not_found:
                LOG.error("error reading TLD cache file %s: %s", self.cache_file, ioe)

    @staticmethod
    def _get_snapshot_tld_extractor():
        snapshot_data = pkgutil.get_data(__name__, '.tld_set_snapshot')
        return json.loads(snapshot_data.decode('utf-8'))

    def _cache_tlds(self, tlds):
        '''Logs a diff of the new TLDs and caches them on disk, according to
        settings passed to __init__.'''
        if LOG.isEnabledFor(logging.DEBUG):
            import difflib
            snapshot_data = pkgutil.get_data(__name__, '.tld_set_snapshot')
            snapshot = sorted(json.loads(snapshot_data.decode('utf-8')))
            new = sorted(tlds)
            LOG.debug('computed TLD diff:\n%s', '\n'.join(difflib.unified_diff(
                snapshot,
                new,
                fromfile=".tld_set_snapshot",
                tofile=self.cache_file
            )))

        if self.cache_file:
            try:
                with open(self.cache_file, 'w') as cache_file:
                    json.dump(tlds, cache_file)
            except IOError as ioe:
                LOG.warning(
                    (
                        "unable to cache TLDs in file %s. This will refresh the "
                        "Public Suffix List over HTTP every app startup. "
                        "Construct your `TLDExtract` with a writable `cache_file` or "
                        "set `cache_file=False` to silence this warning. %s"
                    ),
                    self.cache_file,
                    ioe,
                )


TLD_EXTRACTOR = TLDExtract()


@wraps(TLD_EXTRACTOR.__call__)
def extract(url):
    return TLD_EXTRACTOR(url)


@wraps(TLD_EXTRACTOR.update)
def update(*args, **kwargs):
    return TLD_EXTRACTOR.update(*args, **kwargs)


def get_tlds_from_raw_suffix_list_data(suffix_list_source, include_psl_private_domains=False):
    if include_psl_private_domains:
        text = suffix_list_source
    else:
        text, _, _ = suffix_list_source.partition('// ===BEGIN PRIVATE DOMAINS===')

    tlds = [m.group('suffix') for m in PUBLIC_SUFFIX_RE.finditer(text)]
    return tlds


class _PublicSuffixListTLDExtractor(object):
    """Wrapper around this project's main algo for PSL
    lookups.
    """

    def __init__(self, tlds):
        self.tlds = frozenset(tlds)

    def suffix_index(self, lower_spl):
        """Returns the index of the first suffix label.
        Returns len(spl) if no suffix is found
        """
        length = len(lower_spl)
        for i in range(length):
            maybe_tld = '.'.join(lower_spl[i:])
            exception_tld = '!' + maybe_tld
            if exception_tld in self.tlds:
                return i + 1

            if maybe_tld in self.tlds:
                return i

            wildcard_tld = '*.' + '.'.join(lower_spl[i + 1:])
            if wildcard_tld in self.tlds:
                return i

        return length


def _decode_punycode(label):
    lowered = label.lower()
    looks_like_puny = lowered.startswith('xn--')
    if looks_like_puny:
        try:
            return idna.decode(label.encode('ascii')).lower()
        except (UnicodeError, IndexError):
            pass
    return lowered
