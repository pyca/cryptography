from collections import namedtuple
from abc import ABCMeta, abstractmethod
import json

from text_analysis_helpers.helpers import render_analysis_result, current_date


TextStatistics = namedtuple(
    "TextStatistics",
    ["sentence_count", "word_count", "mean_sentence_word_count",
     "median_sentence_word_count", "min_sentence_word_count",
     "max_sentence_word_count", "average_sentence_word_count",
     "sentence_word_count_std", "sentence_word_count_variance"]
)

WebPage = namedtuple(
    "WebPage",
    ["url", "html"]
)

SocialNetworkData = namedtuple(
    "SocialNetworkData",
    ["opengraph", "twitter"]
)


class BaseAnalysisResult(metaclass=ABCMeta):
    """Base model for all analysis results"""

    DEFAULT_TEMPLATE = None

    def __init__(self):
        creation_date = current_date()

        self.created_at = creation_date.datetime
        self.created_at_timestamp = creation_date.timestamp

    def render(self, template=None):
        """Render the analysis result into the given jinja2 template

        If a template is not given then this object will attempt to render the
        analysis result using the default template of the BaseAnalysisResult
        implementation.

        :param str|none template: the path to a jinja2 template
        """
        template = template or self.DEFAULT_TEMPLATE

        return render_analysis_result(self, template)

    def save(self, output_file, template=None):
        """Save the analysis result to a file

        :param str output_file: the out file
        :param str|None template: render the analysis result using this jinja2
            template. If a template is not given then we will use the default
            template for the BaseAnalysisResult implementation
        :return:
        """
        content = self.render(template=template)

        with open(output_file, "w") as f:
            f.write(content)

    def save_json(self, output_file):
        """Encode to json and save to a file

        :param str output_file: the output file
        """
        with open(output_file, "w") as f:
            f.write(self.as_json())

    @abstractmethod
    def as_dict(self):
        """Convert the analysis result object into a dictionary

        :rtype: dict
        :return: the result object data as a dictionary
        """
        return {
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S %z"),
            "created_at_timestamp": self.created_at_timestamp
        }

    def as_json(self):
        """Convert the analysis result object into a json string

        :rtype: str
        :return: the data encoded in json
        """
        return json.dumps(self.as_dict())


class TextAnalysisResult(BaseAnalysisResult):
    """Text analysis result"""

    DEFAULT_TEMPLATE = "text_analysis_result.html"

    def __init__(self, text, keywords, readability_scores, statistics,
                 summary, named_entities):
        """Create a new TextAnalysisResult object

        :param str text: the text that was analysed
        :param dict[str, int] keywords: the extracted keywords and their scores
        :param dict[str, T] readability_scores: the readability scores
        :param TextStatistics statistics: the text statistics
        :param str summary: the text summary
        :param dict[str, set[str]] named_entities: the extracted named entities
        """
        super(TextAnalysisResult, self).__init__()

        self.text = text
        self.keywords = keywords
        self.readability_scores = readability_scores
        self.statistics = statistics
        self.summary = summary
        self.named_entities = named_entities

    def as_dict(self):
        data = super(TextAnalysisResult, self).as_dict()

        named_entities = {
            named_entity_type: list(self.named_entities[named_entity_type])
            for named_entity_type in self.named_entities
        }

        data.update({
            "text": self.text,
            "keywords": self.keywords,
            "readability_scores": self.readability_scores,
            "statistics": dict(self.statistics._asdict()),
            "summary": self.summary,
            "named_entities": named_entities
        })

        return data


class HtmlAnalysisResult(TextAnalysisResult):
    """Html analysis result"""

    DEFAULT_TEMPLATE = "html_analysis_result.html"

    def __init__(self, url, html, title, social_network_data, text_data,
                 page_content):
        """Create a new HtmlAnalysisResult object

        :param str url: the web page url
        :param str html: the web page content
        :param str title: the web page title
        :param SocialNetworkData social_network_data: the extracted social
            network data
        :param TextAnalysisResult text_data: the text analysis result for the
            text that was extracted from the web page
        :param newspaper.Article page_content: the analysed article data
        """
        super(HtmlAnalysisResult, self).__init__(
            text=text_data.text,
            keywords=text_data.keywords,
            readability_scores=text_data.readability_scores,
            statistics=text_data.statistics,
            summary=text_data.summary,
            named_entities=text_data.named_entities
        )

        self.url = url
        self.html = html
        self.title = title
        self.social_network_data = social_network_data
        self.top_image = page_content.top_image
        self.images = page_content.imgs
        self.movies = page_content.movies

    def as_dict(self):
        data = super(HtmlAnalysisResult, self).as_dict()

        data.update({
            "url": self.url,
            "html": self.html,
            "title": self.title,
            "top_image": self.top_image,
            "images": list(self.images),
            "movies": self.movies,
            "social_network_data": {
                "twitter": self.social_network_data.twitter,
                "opengraph": self.social_network_data.opengraph
            }
        })

        return data
