import contextlib
import ctypes
import struct
from ctypes import c_void_p, c_uint16, c_uint32, c_int32, c_char_p, POINTER

__metaclass__ = type


sec_keychain_ref = sec_keychain_item_ref = c_void_p
OS_status = c_int32


class error:
    item_not_found = -25300
    keychain_denied = -128
    sec_auth_failed = -25293
    plist_missing = -67030


fw = '/System/Library/Frameworks/{name}.framework/Versions/A/{name}'.format
_sec = ctypes.CDLL(fw(name='Security'))
_core = ctypes.CDLL(fw(name='CoreServices'))


SecKeychainOpen = _sec.SecKeychainOpen
SecKeychainOpen.argtypes = (c_char_p, POINTER(sec_keychain_ref))
SecKeychainOpen.restype = OS_status


SecKeychainCopyDefault = _sec.SecKeychainCopyDefault
SecKeychainCopyDefault.argtypes = (POINTER(sec_keychain_ref),)
SecKeychainCopyDefault.restype = OS_status


class Error(Exception):
    @classmethod
    def raise_for_status(cls, status):
        if status == 0:
            return
        if status == error.item_not_found:
            raise NotFound(status, "Item not found")
        if status == error.keychain_denied:
            raise KeychainDenied(status, "Keychain Access Denied")
        if status == error.sec_auth_failed or status == error.plist_missing:
            raise SecAuthFailure(
                status,
                "Security Auth Failure: make sure "
                "python is signed with codesign util",
            )
        raise cls(status, "Unknown Error")


class NotFound(Error):
    pass


class KeychainDenied(Error):
    pass


class SecAuthFailure(Error):
    pass


@contextlib.contextmanager
def open(name):
    ref = sec_keychain_ref()
    if name is None:
        status = SecKeychainCopyDefault(ref)
    else:
        status = SecKeychainOpen(name.encode('utf-8'), ref)
    Error.raise_for_status(status)
    try:
        yield ref
    finally:
        _core.CFRelease(ref)


SecKeychainFindGenericPassword = _sec.SecKeychainFindGenericPassword
SecKeychainFindGenericPassword.argtypes = (
    sec_keychain_ref,
    c_uint32,
    c_char_p,
    c_uint32,
    c_char_p,
    POINTER(c_uint32),  # passwordLength
    POINTER(c_void_p),  # passwordData
    POINTER(sec_keychain_item_ref),  # itemRef
)
SecKeychainFindGenericPassword.restype = OS_status


def find_generic_password(kc_name, service, username):
    username = username.encode('utf-8')
    service = service.encode('utf-8')
    with open(kc_name) as keychain:
        length = c_uint32()
        data = c_void_p()
        status = SecKeychainFindGenericPassword(
            keychain, len(service), service, len(username), username, length, data, None
        )

    Error.raise_for_status(status)

    password = ctypes.create_string_buffer(length.value)
    ctypes.memmove(password, data.value, length.value)
    SecKeychainItemFreeContent(None, data)
    return password.raw.decode('utf-8')


SecKeychainFindInternetPassword = _sec.SecKeychainFindInternetPassword
SecKeychainFindInternetPassword.argtypes = (
    sec_keychain_ref,  # keychainOrArray
    c_uint32,  # serverNameLength
    c_char_p,  # serverName
    c_uint32,  # securityDomainLength
    c_char_p,  # securityDomain
    c_uint32,  # accountNameLength
    c_char_p,  # accountName
    c_uint32,  # pathLength
    c_char_p,  # path
    c_uint16,  # port
    c_uint32,  # SecProtocolType protocol,
    c_uint32,  # SecAuthenticationType authenticationType,
    POINTER(c_uint32),  # passwordLength
    POINTER(c_void_p),  # passwordData
    POINTER(sec_keychain_item_ref),  # itemRef
)
SecKeychainFindInternetPassword.restype = OS_status


class PackedAttributes(type):
    """
    Take the attributes which use magic words
    to represent enumerated constants and generate
    the constants.
    """

    def __new__(cls, name, bases, dict):
        dict.update(
            (key, cls.unpack(val))
            for key, val in dict.items()
            if not key.startswith('_')
        )
        return super().__new__(cls, name, bases, dict)

    @staticmethod
    def unpack(word):
        r"""
        >>> PackedAttributes.unpack(0)
        0
        >>> PackedAttributes.unpack('\x00\x00\x00\x01')
        1
        >>> PackedAttributes.unpack('abcd')
        1633837924
        """
        if not isinstance(word, str):
            return word
        (val,) = struct.unpack('!I', word.encode('ascii'))
        return val


class SecProtocolType(metaclass=PackedAttributes):
    kSecProtocolTypeHTTP = 'http'
    kSecProtocolTypeHTTPS = 'htps'
    kSecProtocolTypeFTP = 'ftp '


class SecAuthenticationType(metaclass=PackedAttributes):
    """
    >>> SecAuthenticationType.kSecAuthenticationTypeDefault
    1684434036
    """

    kSecAuthenticationTypeDefault = 'dflt'
    kSecAuthenticationTypeAny = 0


def find_internet_password(kc_name, service, username):
    username = username.encode('utf-8')
    domain = None
    service = service.encode('utf-8')
    path = None
    port = 0

    with open(kc_name) as keychain:
        length = c_uint32()
        data = c_void_p()
        status = SecKeychainFindInternetPassword(
            keychain,
            len(service),
            service,
            0,
            domain,
            len(username),
            username,
            0,
            path,
            port,
            SecProtocolType.kSecProtocolTypeHTTPS,
            SecAuthenticationType.kSecAuthenticationTypeAny,
            length,
            data,
            None,
        )

    Error.raise_for_status(status)

    password = ctypes.create_string_buffer(length.value)
    ctypes.memmove(password, data.value, length.value)
    SecKeychainItemFreeContent(None, data)
    return password.raw.decode('utf-8')


SecKeychainAddGenericPassword = _sec.SecKeychainAddGenericPassword
SecKeychainAddGenericPassword.argtypes = (
    sec_keychain_ref,
    c_uint32,
    c_char_p,
    c_uint32,
    c_char_p,
    c_uint32,
    c_char_p,
    POINTER(sec_keychain_item_ref),
)
SecKeychainAddGenericPassword.restype = OS_status


def set_generic_password(name, service, username, password):
    username = username.encode('utf-8')
    service = service.encode('utf-8')
    password = password.encode('utf-8')
    with open(name) as keychain:
        item = sec_keychain_item_ref()
        status = SecKeychainFindGenericPassword(
            keychain, len(service), service, len(username), username, None, None, item
        )
        if status:
            if status == error.item_not_found:
                status = SecKeychainAddGenericPassword(
                    keychain,
                    len(service),
                    service,
                    len(username),
                    username,
                    len(password),
                    password,
                    None,
                )
        else:
            status = SecKeychainItemModifyAttributesAndData(
                item, None, len(password), password
            )
            _core.CFRelease(item)

        Error.raise_for_status(status)


SecKeychainAddInternetPassword = _sec.SecKeychainAddInternetPassword
SecKeychainAddInternetPassword.argtypes = (
    sec_keychain_ref,  # keychainOrArray
    c_uint32,  # serverNameLength
    c_char_p,  # serverName
    c_uint32,  # securityDomainLength
    c_char_p,  # securityDomain
    c_uint32,  # accountNameLength
    c_char_p,  # accountName
    c_uint32,  # pathLength
    c_char_p,  # path
    c_uint16,  # port
    c_uint32,  # SecProtocolType protocol,
    c_uint32,  # SecAuthenticationType authenticationType,
    c_uint32,  # passwordLength
    c_void_p,  # passwordData
    POINTER(sec_keychain_item_ref),  # itemRef
)
SecKeychainAddInternetPassword.restype = OS_status


def set_internet_password(name, service, username, password):
    username = username.encode('utf-8')
    domain = None
    service = service.encode('utf-8')
    password = password.encode('utf-8')
    path = None
    port = 0
    with open(name) as keychain:
        # TODO: Use update or set technique as seen in set_generic_password
        status = SecKeychainAddInternetPassword(
            keychain,
            len(service),
            service,
            0,
            domain,
            len(username),
            username,
            0,
            path,
            port,
            SecProtocolType.kSecProtocolTypeHTTPS,
            SecAuthenticationType.kSecAuthenticationTypeAny,
            len(password),
            password,
            None,
        )

        Error.raise_for_status(status)


SecKeychainItemModifyAttributesAndData = _sec.SecKeychainItemModifyAttributesAndData
SecKeychainItemModifyAttributesAndData.argtypes = (
    sec_keychain_item_ref,
    c_void_p,
    c_uint32,
    c_void_p,
)
SecKeychainItemModifyAttributesAndData.restype = OS_status

SecKeychainItemFreeContent = _sec.SecKeychainItemFreeContent
SecKeychainItemFreeContent.argtypes = (c_void_p, c_void_p)
SecKeychainItemFreeContent.restype = OS_status

SecKeychainItemDelete = _sec.SecKeychainItemDelete
SecKeychainItemDelete.argtypes = (sec_keychain_item_ref,)
SecKeychainItemDelete.restype = OS_status


def delete_generic_password(name, service, username):
    username = username.encode('utf-8')
    service = service.encode('utf-8')
    with open(name) as keychain:
        length = c_uint32()
        data = c_void_p()
        item = sec_keychain_item_ref()
        status = SecKeychainFindGenericPassword(
            keychain, len(service), service, len(username), username, length, data, item
        )

    Error.raise_for_status(status)

    SecKeychainItemDelete(item)
    _core.CFRelease(item)
