class TextAnalysisHelpersException(Exception):
    """Base text analysis helpers exception"""
    pass


class WebPageDownloadError(TextAnalysisHelpersException):
    """Exception that is raised if there was an error while downloading the
    contents of a web page"""

    def __init__(self, message=None, url=None, status_code=None,
                 response=None):
        """Create a new WebPageDownloadError object

        :param str|None message: the description of the error
        :param str|None url: the url that caused the error to occur
        :param int|None status_code: the response status code
        :param str|None response: the response text
        """
        super(WebPageDownloadError, self).__init__(
            message, url, status_code, response)

        self.message = message
        self.url = url
        self.status_code = status_code
        self.response = response


class HtmlAnalysisError(TextAnalysisHelpersException):
    """Exchaption raised when an error occurs during html analysis"""
    pass


class ContentExtractionFailed(HtmlAnalysisError):
    """Exception that is raised when no content could be extracted"""
    pass
