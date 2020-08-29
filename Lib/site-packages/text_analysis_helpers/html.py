import logging

from bs4 import BeautifulSoup

from text_analysis_helpers.downloaders import download_web_page
from text_analysis_helpers.exceptions import ContentExtractionFailed
from text_analysis_helpers.models import HtmlAnalysisResult, SocialNetworkData
from text_analysis_helpers.processors.html import (
    extract_opengraph_data, extract_page_content, extract_page_data,
    extract_twitter_card
)
from text_analysis_helpers.text import TextAnalyser


logger = logging.getLogger(__name__)


class HtmlAnalyser(object):
    """Html content analyser"""

    def __init__(self, keyword_stop_list=None):
        self.__keyword_stop_list = keyword_stop_list
        self.__text_analyser = TextAnalyser(keyword_stop_list)

    def analyse_url(self, url, timeout=5, headers=None, verify=True):
        """Download and analyse the contents of the given url

        :param str url: the url to analyse
        :param int timeout: the request timeout
        :param dict|None headers: the headers to add to the request
        :param boolean verify: verify ssl
        :rtype: HtmlAnalysisResult
        :return: the analysis result
        """
        web_page = download_web_page(
            url=url,
            timeout=timeout,
            headers=headers,
            verify=verify
        )

        return self.analyse(web_page)

    def analyse(self, web_page):
        """Analyse the web page contents

        :param text_analysis_helpers.models.WebPage web_page: the wb page
            contents
        :rtype: HtmlAnalysisResult
        :return: the analysis result
        """
        page_content = extract_page_content(web_page.url, web_page.html)
        if not page_content.text:
            raise ContentExtractionFailed()

        text_analysis_result = self.__text_analyser.analyse(page_content.text)
        soup = BeautifulSoup(web_page.html, "html.parser")
        page_data = extract_page_data(soup)
        opengraph_data = extract_opengraph_data(web_page.html)
        twitter_card = extract_twitter_card(soup)

        return HtmlAnalysisResult(
            url=web_page.url,
            html=web_page.html,
            title=page_data["title"],
            social_network_data=SocialNetworkData(
                opengraph=opengraph_data,
                twitter=twitter_card
            ),
            text_data=text_analysis_result,
            page_content=page_content
        )
