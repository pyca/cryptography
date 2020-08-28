import itertools
from collections import defaultdict

from nltk import sent_tokenize, word_tokenize
from nltk.data import load as nltk_data_load
from nltk.tag.perceptron import PerceptronTagger
from nltk.tree import Tree
import numpy as np


from text_analysis_helpers.models import TextAnalysisResult, TextStatistics
from text_analysis_helpers.processors.text import (
    extract_keywords, calculate_readability_scores, create_summary
)


class TextAnalyser(object):
    """Text analyser"""

    MULTICLASS_NE_CHUNKER = \
        "chunkers/maxent_ne_chunker/english_ace_multiclass.pickle"

    def __init__(self, keyword_stop_list=None):
        self.__keyword_stop_list = keyword_stop_list

        self.__pos_tagger = PerceptronTagger()
        self.__ne_chunker = nltk_data_load(self.MULTICLASS_NE_CHUNKER)

    def analyse_file(self, filename):
        """Analyse the contents of a file

        :param str filename: the path to a file
        :rtype: TextAnalysisResult
        :return: the analysis result
        """
        with open(filename, "r") as f:
            return self.analyse(f.read())

    def _calculate_text_statistics(self, sentences, sentence_words):
        """Calculate the text statistics

        :param list[str] sentences: a list with the text sentences
        :param list[list[str]] sentence_words: a list with the sentences that
            have been tokenized into separate words
        :rtype: TextStatistics
        :return: the calculated text statistics
        """
        words = list(itertools.chain(*sentence_words))

        sentence_word_counts = np.array(
            [len(sentence) for sentence in sentence_words])

        return TextStatistics(
            sentence_count=len(sentences),
            word_count=len(words),
            mean_sentence_word_count=float(sentence_word_counts.mean()),
            median_sentence_word_count=float(np.median(sentence_word_counts)),
            min_sentence_word_count=int(sentence_word_counts.min()),
            max_sentence_word_count=int(sentence_word_counts.max()),
            average_sentence_word_count=float(
                np.average(sentence_word_counts)),
            sentence_word_count_std=float(sentence_word_counts.std()),
            sentence_word_count_variance=float(sentence_word_counts.var())
        )

    def _extract_named_entities(self, sentence_words):
        """Extract the named entities from the sentences

        The result from this method is a dictionary with the named entity types
        as keys and a set of the names entities as values

        :param list[list[str]] sentence_words: a list with the sentences that
            have been tokenized into separate words
        :rtype: dict[str: set]
        :return: the extracted dictionary words
        """
        tagged_sentences = [self.__pos_tagger.tag(sentence)
                            for sentence in sentence_words]
        chunked_sentences = [self.__ne_chunker.parse(sentence)
                             for sentence in tagged_sentences]

        named_entities = defaultdict(set)
        for sentence in chunked_sentences:
            for item in sentence:
                if isinstance(item, Tree):
                    ne_type = item.label()
                    entity = " ".join(
                        [
                            entity_component[0]
                            for entity_component in item.leaves()
                        ]
                    )

                    named_entities[ne_type].add(entity)

        return dict(named_entities)

    def analyse(self, text):
        """Analyse the given text

        :param str text: the text to analyse
        :rtype: TextAnalysisResult
        :return: the analysis result
        """
        readability_scores = calculate_readability_scores(text)

        keywords = None
        if isinstance(text, str) and len(text) != 0:
            keywords = extract_keywords(
                text=text,
                keyword_stop_list=self.__keyword_stop_list
            )

        sentences = sent_tokenize(text)
        sentence_words = [word_tokenize(sentence) for sentence in sentences]

        statistics = self._calculate_text_statistics(sentences, sentence_words)
        summary = create_summary(text)
        named_entities = self._extract_named_entities(sentence_words)

        return TextAnalysisResult(
            text=text,
            keywords=keywords,
            readability_scores=readability_scores,
            statistics=statistics,
            summary=summary,
            named_entities=named_entities
        )
