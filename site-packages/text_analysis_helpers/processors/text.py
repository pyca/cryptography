from rake.rake import Rake
from rake.stoplists import get_stoplist_file_path
from textstat.textstat import textstat
from gensim.summarization.summarizer import summarize


def extract_keywords(text, keyword_stop_list=None):
    keyword_stop_list = keyword_stop_list or "SmartStoplist.txt"
    rake = Rake(get_stoplist_file_path(keyword_stop_list))

    keywords = rake.run(text)

    keywords = {
        keyword: score
        for keyword, score in keywords
    }

    return keywords


def calculate_readability_scores(text):
    score_functions = [
        "flesch_reading_ease", "smog_index", "flesch_kincaid_grade",
        "coleman_liau_index", "automated_readability_index",
        "dale_chall_readability_score", "difficult_words",
        "linsear_write_formula", "gunning_fog", "text_standard"
    ]

    return {
        score_function: getattr(textstat, score_function)(text)
        for score_function in score_functions
    }


def create_summary(text):
    return summarize(text)
