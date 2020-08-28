from os import path


def get_stoplist_file_path(stoplist):
    stoplist_file_path = path.join(path.abspath(path.dirname(__file__)), "data", "stoplists", stoplist)

    return stoplist_file_path
