from __future__ import absolute_import, print_function
import argparse
from readme_renderer.rst import render
import sys


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Renders a .rst README to HTML",
    )
    parser.add_argument('input', help="Input README file",
                        type=argparse.FileType('r'))
    parser.add_argument('-o', '--output', help="Output file (default: stdout)",
                        type=argparse.FileType('w'), default='-')
    args = parser.parse_args()

    rendered = render(args.input.read(), stream=sys.stderr)
    if rendered is None:
        sys.exit(1)
    print(rendered, file=args.output)
