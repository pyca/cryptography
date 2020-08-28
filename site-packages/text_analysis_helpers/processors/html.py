from logging import getLogger

from newspaper import Article
from opengraph.opengraph import OpenGraph


logger = getLogger(__name__)


def extract_page_content(url, html_content):
    article = Article(url)
    article.download(input_html=html_content)
    article.parse()

    return article


def extract_page_data(soup):
    title = soup.find("title")

    return {
        "title": title.text if title else None
    }


def extract_opengraph_data(html_content):
    opengraph = OpenGraph()
    opengraph.parser(html_content)

    return opengraph if opengraph.is_valid() else None


def extract_twitter_card(soup):
    card = {}

    for meta in soup.find_all("meta"):
        name = meta.get("name", "")
        if name.startswith("twitter:"):
            items = name.split(":")
            if len(items) < 2:
                msg = "Invalid twitter card value: twitter_card(%s)"
                logger.warning(msg, name)
                continue
            card[":".join(items[1:])] = meta.get("content")

    # if twitter card data could not be extracted then return None instead
    # of an empty dictionary
    if len(card) == 0:
        logger.warning("failed to extract twitter card")
        card = None

    return card
