"""Utilities for working with projects."""

from collections import namedtuple, UserDict, UserList
from difflib import SequenceMatcher


class InvalidProjectError(ValueError):
    """The project cannot be loaded because it is invalid."""

    pass


class InvalidVariableError(InvalidProjectError):
    """A variable is invalid."""

    def __init__(self, name, message):
        super().__init__('{} {}'.format(name, message))


class InvalidTaskError(InvalidProjectError):
    """A task is invalid."""

    def __init__(self, name, message):
        super().__init__('{} {}'.format(name, message))


class InvalidStepError(InvalidProjectError):
    """A step is invalid."""

    pass


class NoSuchTaskError(KeyError):
    """
    A task cannot be found.

    Parameters
    ----------
    similarities
        A list of similarly named tasks.
    """

    def __init__(self, similarities):
        self.similarities = similarities


_Variable = namedtuple('_Variable', ['name', 'description', 'default'])


class Variable(_Variable):
    def __str__(self):
        return '{} ({})'.format(self.name, self.description)


Task = namedtuple('Task', ['name', 'description', 'variables', 'steps',
                  'dependencies'])

Step = namedtuple('Step', ['type', 'args'])


class VariableCollection(UserDict):
    """
    A collection of variables.

    Parameters
    ----------
    config : dict
        The configuration for the variable collection, generally this comes
        from a section of the project configuration.
    """

    def __init__(self, config=None):
        super().__init__()

        if config is not None:
            self._load_from_config(config)

    def _load_from_config(self, config):
        for name, conf in config.items():
            self[name] = self._load_variable_from_config(name, conf)

    @staticmethod
    def _load_variable_from_config(name, config):
        default = config.get('default')

        try:
            description = config['description']
        except KeyError:
            raise InvalidVariableError(name, 'missing a description.')

        return Variable(name, description, default)

    def __str__(self):
        return ', '.join(self.keys())


class StepCollection(UserList):
    """
    A collection of steps.

    Parameters
    ----------
    config : dict
        The configuration for the step collection, generally this comes from a
        section of the task configuration.
    """

    def __init__(self, config=None):
        super().__init__()

        if config is not None:
            self._load_from_config(config)

    def _load_from_config(self, config):
        if isinstance(config, str):
            self.append(Step('command', config))
        elif isinstance(config, list):
            for conf in config:
                self._load_from_config(conf)
        elif isinstance(config, dict):
            self.append(self._load_step_from_config(config))
        else:
            raise TypeError('config should be a str, list or dict.')

    @staticmethod
    def _load_step_from_config(config):
        if len(config) != 1:
            raise InvalidStepError('Malformed step.')

        type = list(config.keys())[0]
        return Step(type, config[type])

    def __str__(self):
        return ', '.join(self.keys())


class TaskCollection(UserDict):
    """
    A collection of tasks.

    Parameters
    ----------
    config : dict
        The configuration for the task collection, generally this comes from a
        section of the project configuration.
    """

    default_descriptions = {
        'bootstrap': 'Resolve all dependencies that an application requires to run.',
        'test': 'Run the tests.',
        'ci': 'Run the tests in an environment suitable for continous integration.',
        'console': 'Launch a console for the application.',
        'server': 'Launch the application server locally.',
        'setup': 'Setup the application for the first time after cloning.',
        'update': 'Update the application to run for its current checkout.',
        'deploy': 'Deploy the application to production.',
        'lint': 'Check the application for linting errors, this task is likely to be called by the test task.',
        'release': 'Make a new release of the software.',
        'docs': 'Generate the documentation.'
    }

    def __init__(self, config=None):
        super().__init__()

        if config is not None:
            self._load_from_config(config)

    def _load_from_config(self, config):
        for name, conf in config.items():
            self[name] = self._load_task_from_config(name, conf)

    @staticmethod
    def _load_task_from_config(name, config):
        try:
            description = config['description']
        except KeyError:
            try:
                description = TaskCollection.default_descriptions[name]
            except KeyError:
                raise InvalidTaskError(name, 'missing a description.')

        try:
            variables = VariableCollection(config.get('variables'))
        except InvalidVariableError as e:
            msg = 'has invalid variables: {}'.format(e)
            raise InvalidTaskError(name, msg)

        try:
            steps = StepCollection(config.get('steps'))
        except InvalidStepError as e:
            msg = 'has invalid steps: {}'.format(e)
            raise InvalidTaskError(name, msg)

        dependencies = config.get('after', [])

        return Task(name, description, variables, steps, dependencies)

    def __str__(self):
        return ', '.join(self.keys())


class Project:
    """
    A project contains variables and tasks.

    Parameters
    ----------
    config : dict
        This configuration for this project, generally this comes from a
        ``Mofile`` file.
    """

    def __init__(self, config, path):
        self.config = config
        self.path = path

        try:
            self.name = config['name']
        except KeyError:
            self.name = self._guess_name()

        self.variables = VariableCollection(config.get('variables'))
        self.tasks = TaskCollection(config.get('tasks'))

        if not self.tasks:
            raise InvalidProjectError('No tasks defined.')

        self.tasks['help'] = self._create_help_task()

    def find_task(self, name):
        """
        Find a task by name.

        If a task with the exact name cannot be found, then tasks with similar
        names are searched for.

        Returns
        -------
        Task
            If the task is found.

        Raises
        ------
        NoSuchTaskError
            If the task cannot be found.
        """

        try:
            return self.tasks[name]
        except KeyError:
            pass

        similarities = []

        for task_name, task in self.tasks.items():
            ratio = SequenceMatcher(None, name, task_name).ratio()
            if ratio >= 0.75:
                similarities.append(task)

        if len(similarities) == 1:
            return similarities[0]
        else:
            raise NoSuchTaskError(similarities)

    @staticmethod
    def _create_help_task():
        variables = VariableCollection()
        variables['topic'] = Variable('task', 'Which task to get help about.',
                                      None)

        steps = StepCollection()
        steps.append(Step('help', None))

        return Task('help', 'Get help about a task.', variables, steps, [])

    def __str__(self):
        return '{} ({})'.format(self.name, self.tasks)

    def _guess_name(self):
        return self.path.name
