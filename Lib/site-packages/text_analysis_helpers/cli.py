from argparse import ArgumentParser

from text_analysis_helpers.html import HtmlAnalyser
from text_analysis_helpers.text import TextAnalyser


def analyse_url(args):
    analyser = HtmlAnalyser()
    analysis_result = analyser.analyse_url(args.url)

    if args.json:
        analysis_result.save_json(args.output)
    else:
        analysis_result.save(args.output)


def analyse_file(args):
    analyser = TextAnalyser()
    analysis_result = analyser.analyse_file(args.filename)

    if args.json:
        analysis_result.save_json(args.output)
    else:
        analysis_result.save(args.output)


def get_arguments():
    parser = ArgumentParser()
    subparsers = parser.add_subparsers()

    url_parser = subparsers.add_parser(
        "analyse-url",
        description="analyse the contents of a url",
        help="analyse the contents of a url"
    )

    url_parser.add_argument(
        "--output",
        default="analysis_result.html",
        help="the name of the file in which to save the result"
    )

    url_parser.add_argument("--json", action="store_true")
    url_parser.add_argument("url", help="the url to analyse")
    url_parser.set_defaults(func=analyse_url)

    file_parser = subparsers.add_parser(
        "analyse-file",
        description="analyse the contents of a file",
        help="analyse the contents of a file"
    )

    file_parser.add_argument(
        "--output",
        default="analysis_result.html",
        help="the name of the file in which to save the result"
    )

    file_parser.add_argument("--json", action="store_true")
    file_parser.add_argument("filename", help="the file to analyse")
    file_parser.set_defaults(func=analyse_file)

    return parser.parse_args()


def main():
    args = get_arguments()
    args.func(args)
