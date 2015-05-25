from __future__ import unicode_literals

import base64

from six.moves.urllib.parse import quote, urlencode


__all__ = ['get_provisioning_uri']


def get_provisioning_uri(otp, account_name, issuer=None, counter=None):
    """Generates a provisioning URI which can be recognized by Two-Factor
    Authentication Apps. See also: http://git.io/vkvvY

    :param otp: An instance of
                :class:`cryptography.hazmat.primitives.twofactor.hotp.HOTP` or
                :class:`cryptography.hazmat.primitives.twofactor.totp.TOTP`.
    :param account_name: The display name of account, such as
                         ``'Alice Smith'`` or ``'alice@example.com'``.
    :param issuer: The display name of issuer.
    :param counter: The current value of counter. It is required for HOTP.
    :return: The URI string.
    :raises RuntimeError: if counter is missing but otp type is HOTP
    """
    hotp = getattr(otp, '_hotp', otp)

    parameters = [
        ('digits', hotp._length),
        ('secret', base64.b32encode(hotp._key)),
        ('algorithm', hotp._algorithm.name.upper()),
    ]

    if issuer is not None:
        parameters.append(('issuer', issuer))

    if hotp is otp:
        if counter is None:
            raise RuntimeError('"counter" is required for HOTP')
        parameters.append(('counter', int(counter)))

    if hasattr(otp, '_time_step'):
        parameters.append(('period', int(otp._time_step)))

    uriparts = {
        'type': otp.__class__.__name__.lower(),
        'label': ('%s:%s' % (quote(issuer), quote(account_name)) if issuer
                  else quote(account_name)),
        'parameters': urlencode(parameters),
    }
    return 'otpauth://{type}/{label}?{parameters}'.format(**uriparts)
