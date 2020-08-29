import requests

from text_analysis_helpers.exceptions import WebPageDownloadError
from text_analysis_helpers.models import WebPage


def download_web_page(url, timeout=5, **kwargs):
    """Download a web page

    :param str url: the url of the web page
    :param int timeout: the request timeout
    :param kwargs: additional arguments to pass to the `requests.get`
        method
    :rtype: WebPage
    :return: the web page contents
    """
    _kwargs = {
        "timeout": timeout
    }
    _kwargs.update(kwargs)

    response = requests.get(url, **_kwargs)

    if response.status_code < 200 or response.status_code >= 300:
        raise WebPageDownloadError(
            message="failed to download web page",
            url=url,
            status_code=response.status_code,
            response=response.text
        )

    return WebPage(
        url=url,
        html=response.text
    )
