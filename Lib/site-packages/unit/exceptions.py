"""Exception classes."""

__all__ = [
    # Message errors
    'MessageError', 'MessageParseError',

    # Base class for all HTTP exceptions
    'HTTPException',

    # Informational exceptions (1xx)
    'InformationalException',
    'Continue', 'SwitchingProtocols', 'Processing',

    # Success exceptions (2xx)
    'SuccessException',
    'OK', 'Created', 'Accepted', 'NonAuthoritativeInformation', 'NoContent',
    'ResetContent', 'PartialContent', 'MultiStatus', 'AlreadyReported',
    'IMUsed',

    # Redirect exceptions (3xx)
    'RedirectException',
    'MovedPermanently', 'Found', 'SeeOther', 'TemporaryRedirect',

    # Client exceptions (4xx)
    'ClientException',
    'BadRequest', 'Unauthorized', 'PaymentRequired', 'Forbidden', 'NotFound',
    'MethodNotAllowed', 'NotAcceptable', 'ProxyAuthenticationRequired',
    'RequestTimeout', 'Conflict', 'Gone', 'LengthRequired',
    'PreconditionFailed', 'RequestEntityTooLarge', 'RequestURITooLarge',
    'UnsupportedMediaType', 'RequestedRangeNotSatisfiable',
    'ExpectationFailed', 'UnprocessableEntity', 'Locked', 'FailedDependency',
    'UpgradeRequired', 'PreconditionRequired', 'TooManyRequests',
    'RequestHeaderFieldsTooLarge',

    # Server exceptions (5xx)
    'ServerException',
    'InternalServerError', 'NotImplemented', 'BadGateway',
    'ServiceUnavailable', 'GatewayTimeout', 'HTTPVersionNotSupported'
]


class MessageError(Exception):
    """Base class for message errors."""


class MessageParseError(MessageError):
    """Base class for message parsing errors."""


class HTTPException(Exception):
    """Base class for all HTTP exceptions."""
    code = None
    phrase = None
    description = None


# Informational exceptions (1xx)

class InformationalException(HTTPException):
    """Base class for all informational exceptions."""


class Continue(InformationalException):
    code = 100
    phrase = 'Continue'
    description = 'Request received, please continue'


class SwitchingProtocols(InformationalException):
    code = 101
    phrase = 'Switching Protocols'
    description = 'Switching to new protocol; obey Upgrade header'


class Processing(InformationalException):
    code = 102
    phrase = 'Processing'
    description = 'Processing'


# Success exceptions (2xx)

class SuccessException(HTTPException):
    """Base class for all success exceptions."""


class OK(SuccessException):
    code = 200
    phrase = 'OK'
    description = 'Request fulfilled, document follows'


class Created(SuccessException):
    code = 201
    phrase = 'Created'
    description = 'Document created, URL follows'


class Accepted(SuccessException):
    code = 202
    phrase = 'Accepted'
    description = 'Request accepted, processing continues off-line'


class NonAuthoritativeInformation(SuccessException):
    code = 203
    phrase = 'Non-Authoritative Information'
    description = 'Request fulfilled from cache'


class NoContent(SuccessException):
    code = 204
    phrase = 'No Content'
    description = 'Request fulfilled, nothing follows'


class ResetContent(SuccessException):
    code = 205
    phrase = 'Reset Content'
    description = 'Clear input form for further input'


class PartialContent(SuccessException):
    code = 206
    phrase = 'Partial Content'
    description = 'Partial content follows'


class MultiStatus(SuccessException):
    code = 207
    phrase = 'Multi-Status'
    description = 'Multi-Status'


class AlreadyReported(SuccessException):
    code = 208
    phrase = 'Already Reported'
    description = 'Already Reported'


class IMUsed(SuccessException):
    code = 226
    phrase = 'IM Used'
    description = 'IM Used'


# Redirect exceptions (3xx)

class RedirectException(HTTPException):
    """Base class for all redirect exceptions."""
    new_url = None


class MovedPermanently(RedirectException):
    code = 301
    phrase = 'Moved Permanently'
    description = 'Object moved permanently -- see URI list'


class Found(RedirectException):
    code = 302
    phrase = 'Found'
    description = 'Object moved temporarily -- see URI list'


class SeeOther(RedirectException):
    code = 303
    phrase = 'See Other'
    description = 'Object moved -- see Method and URL list'


class TemporaryRedirect(RedirectException):
    code = 307
    phrase = 'Temporary Redirect'
    description = 'Object moved temporarily -- see URI list'


# Client exceptions (4xx)

class ClientException(HTTPException):
    """Base class for all client exceptions."""


class BadRequest(ClientException):
    code = 400
    phrase = 'Bad Request'
    description = 'Bad request syntax or unsupported method'


class Unauthorized(ClientException):
    code = 401
    phrase = 'Unauthorized'
    description = 'No permission -- see authorization schemes'


class PaymentRequired(ClientException):
    code = 402
    phrase = 'Payment Required'
    description = 'No payment -- see charging schemes'


class Forbidden(ClientException):
    code = 403
    phrase = 'Forbidden'
    description = 'Request forbidden -- authorization will not help'


class NotFound(ClientException):
    code = 404
    phrase = 'Not Found'
    description = 'Nothing matches the given URI'


class MethodNotAllowed(ClientException):
    code = 405
    phrase = 'Method Not Allowed'
    description = 'Specified method is invalid for this resource'


class NotAcceptable(ClientException):
    code = 406
    phrase = 'Not Acceptable'
    description = 'URI not available in preferred format'


class ProxyAuthenticationRequired(ClientException):
    code = 407
    phrase = 'Proxy Authentication Required'
    description = 'You must authenticate with this proxy before proceeding'


class RequestTimeout(ClientException):
    code = 408
    phrase = 'Request Timeout'
    description = 'Request timed out; try again later'


class Conflict(ClientException):
    code = 409
    phrase = 'Conflict'
    description = 'Request conflict'


class Gone(ClientException):
    code = 410
    phrase = 'Gone'
    description = 'URI no longer exists and has been permanently removed'


class LengthRequired(ClientException):
    code = 411
    phrase = 'Length Required'
    description = 'Client must specify Content-Length'


class PreconditionFailed(ClientException):
    code = 412
    phrase = 'Precondition Failed'
    description = 'Precondition in headers is false'


class RequestEntityTooLarge(ClientException):
    code = 413
    phrase = 'Request Entity Too Large'
    description = 'Entity is too large'


class RequestURITooLarge(ClientException):
    code = 414
    phrase = 'Request-URI Too Long'
    description = 'URI is too long'


class UnsupportedMediaType(ClientException):
    code = 415
    phrase = 'Unsupported Media Type'
    description = 'Entity body in unsupported format'


class RequestedRangeNotSatisfiable(ClientException):
    code = 416
    phrase = 'Requested Range Not Satisfiable'
    description = 'Cannot satisfy request range'


class ExpectationFailed(ClientException):
    code = 417
    phrase = 'Expectation Failed'
    description = 'Expect condition could not be satisfied'


class UnprocessableEntity(ClientException):
    code = 422
    phrase = 'Unprocessable Entity'
    description = ''


class Locked(ClientException):
    code = 423
    phrase = 'Locked'
    description = 'Locked'


class FailedDependency(ClientException):
    code = 424
    phrase = 'Failed Dependency'
    description = 'Failed Dependency'


class UpgradeRequired(ClientException):
    code = 426
    phrase = 'Upgrade Required'
    description = 'Upgrade Required'


class PreconditionRequired(ClientException):
    code = 428
    phrase = 'Precondition Required'
    description = 'The origin server requires the request to be conditional'


class TooManyRequests(ClientException):
    code = 429
    phrase = 'Too Many Requests'
    description = 'The user has sent too many requests in a given amount of ' \
                  'time ("rate limiting") '


class RequestHeaderFieldsTooLarge(ClientException):
    code = 431
    phrase = 'Request Header Fields Too Large'
    description = 'The server is unwilling to process the request because ' \
                  'its header fields are too large '


# Server exceptions (5xx)

class ServerException(HTTPException):
    """Base class for all server exceptions."""


class InternalServerError(ServerException):
    code = 500
    phrase = 'Internal Server Error'
    description = 'Server got itself in trouble'


class NotImplemented(ServerException):
    code = 501
    phrase = 'Not Implemented'
    description = 'Server does not support this operation'


class BadGateway(ServerException):
    code = 502
    phrase = 'Bad Gateway'
    description = 'Invalid responses from another server/proxy'


class ServiceUnavailable(ServerException):
    code = 503
    phrase = 'Service Unavailable'
    description = 'The server cannot process the request due to a high load'


class GatewayTimeout(ServerException):
    code = 504
    phrase = 'Gateway Timeout'
    description = 'The gateway server did not receive a timely response'


class HTTPVersionNotSupported(ServerException):
    code = 505
    phrase = 'HTTP Version Not Supported'
    description = 'Cannot fulfill request'
