import json

import colorama
from colorama import Fore, Style

from .events import Event
from .project import Step, StepCollection, Task, Variable, VariableCollection


class Frontend:
    """A frontend takes output from the runner and displays it to the user."""

    def begin(self):
        """Begin processing output."""
        pass

    def end(self):
        """End processing output."""
        pass

    def output(self, event):
        """Process a single event."""
        pass


class Debug(Frontend):
    """The debug frontend simply prints the raw events."""

    def output(self, event):
        print(event)


class Human(Frontend):
    """
    The human frontend provides colourful textual output useful for humans
    to read.
    """

    ignored_events = (
        'FindingTask', 'StartingTask', 'RunningStep', 'FinishedTask'
    )

    def begin(self):
        colorama.init()
        print()

    def end(self):
        print()

    def output(self, event):
        character_style = Fore.BLUE + Style.BRIGHT

        if event.name in self.ignored_events:
            return

        if event.name == 'RunningTask':
            character = 'λ'
            text = 'Running task: {}{}'.format(Style.NORMAL,
                                               event.args['task'].name)
            text_style = Style.BRIGHT
        elif event.name == 'SkippingTask':
            character = 'λ'
            character_style = Fore.YELLOW + Style.BRIGHT
            text = 'Skipping task: {}{}'.format(Style.NORMAL,
                                                event.args['name'])
            text_style = Style.DIM
        elif event.name == 'RunningCommand':
            character = '>'
            text = 'Executing: {}{}'.format(Style.NORMAL,
                                            event.args['command'])
            text_style = Style.BRIGHT
        elif event.name == 'CommandOutput':
            character = ' '
            text = event.args['output']
            text_style = Style.DIM
            if event.args['pipe'] == 'stderr':
                text_style += Fore.RED
        elif event.name == 'CommandFailedEvent':
            character = '!'
            character_style = Fore.RED + Style.BRIGHT
            text = 'Command failed!'
            text_style = Fore.RED
        elif event.name == 'UndefinedVariableError':
            character = '!'
            character_style = Fore.RED + Style.BRIGHT
            text = 'Undefined variable: {}'.format(event.args['variable'])
            text_style = Fore.RED
        elif event.name == 'TaskNotFound':
            character = '!'
            character_style = Fore.RED + Style.BRIGHT
            text = 'No such task: {}'.format(event.args['name'])
            if event.args['similarities']:
                text += ' Did you mean? {}' \
                    .format(', '.join(event.args['similarities']))
            text_style = Fore.RED
        elif event.name == 'HelpStepOutput':
            print()
            for line in event.args['output'].splitlines():
                print('', line)
            return
        else:
            character = '?'
            character_style = Fore.YELLOW + Style.BRIGHT
            text = f'Unknown event: {event}'
            text_style = Fore.YELLOW

        print(' {}{}{} {}{}{}'.format(
            character_style, character, Style.RESET_ALL,
            text_style, text, Style.RESET_ALL
        ))


class SerialisingFrontend(Frontend):
    """
    A serialising frontend first serialises events into dictionaries before
    outputting.
    """

    def serialise(self, obj):
        """
        Take an object from the project or the runner and serialise it into a
        dictionary.

        Parameters
        ----------
        obj : object
            An object to serialise.

        Returns
        -------
        object
            A serialised version of the input object.
        """

        if isinstance(obj, (list, VariableCollection, StepCollection)):
            return [self.serialise(element) for element in obj]
        elif isinstance(obj, dict):
            return {k: self.serialise(v) for k, v in obj.items()}
        elif isinstance(obj, str):
            return obj
        elif isinstance(obj, (Event, Task, Variable, Step)):
            return self.serialise(obj._asdict())
        elif obj is None:
            return None
        else:
            raise TypeError(type(obj))


class Json(SerialisingFrontend):
    """Display the output as line terminated JSON objects."""

    def output(self, event):
        print(json.dumps(self.serialise(event)))


MAPPINGS = {
    'human': Human,
    'debug': Debug,
    'json': Json
}
