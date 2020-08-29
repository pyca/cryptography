from argparse import ArgumentParser
import sys

from . import mofile
from .frontend import MAPPINGS as FRONTEND_MAPPINGS
from .runner import Runner


def parse_variables(args):
    """
    Parse variables as passed on the command line.

    Returns
    -------
    dict
        Mapping variable name to the value.
    """

    variables = {}

    if args is not None:
        for variable in args:
            tokens = variable.split('=')
            name = tokens[0]
            value = '='.join(tokens[1:])
            variables[name] = value

    return variables


def parse_args():
    parser = ArgumentParser()
    parser.add_argument('-f', '--file', default='Mofile')
    parser.add_argument('-v', '--var', dest='variables', nargs='*')
    parser.add_argument('--frontend', default='human',
                        choices=FRONTEND_MAPPINGS.keys())
    parser.add_argument('tasks', metavar='task', nargs='*')
    return parser.parse_args()


def run(args):
    project = mofile.load(args.file)

    variables = parse_variables(args.variables)

    runner = Runner(project, variables)

    if args.tasks:
        for task in args.tasks:
            runner.queue_task(task)

        yield from runner.run()
    else:
        yield from runner.help()


def main():
    """Run the CLI."""

    args = parse_args()

    frontend = FRONTEND_MAPPINGS[args.frontend]()

    frontend.begin()

    try:
        for event in run(args):
            frontend.output(event)
    finally:
        frontend.end()
