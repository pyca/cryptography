from . import events, steps
from .project import NoSuchTaskError, Step


class StopTask(StopIteration):
    pass


class Runner:
    """A runner takes a project and some variables and runs it."""

    def __init__(self, project, variables):
        self.project = project
        self.variables = variables

        self.tasks_run = []
        self.task_queue = []

    def run(self):
        """Run any queued tasks."""

        for name in self.task_queue:
            yield from self.run_task(name)

    def help(self):
        """Run a help event."""

        yield events.help(self.project)

    def queue_task(self, name):
        """Queue a task for execution."""

        self.task_queue.append(name)

    def find_task(self, name):
        """Find a task by name."""

        return self.project.find_task(name)

    def resolve_variables(self, task):
        """
        Resolve task variables based on input variables and the default
        values.

        Raises
        ------
        LookupError
            If a variable is missing.
        """

        variables = {**task.variables, **self.project.variables}

        values = {}

        for variable in variables.values():
            value = self.variables.get(variable.name) or variable.default
            if value is None:
                raise LookupError(variable)
            values[variable.name] = value

        return values

    def run_task(self, name):
        """Run a task."""

        if name in self.tasks_run:
            yield events.skipping_task(name)
        else:
            yield events.finding_task(name)

            try:
                task = self.find_task(name)
            except NoSuchTaskError as e:
                yield events.task_not_found(name, e.similarities)
                raise StopTask

            yield events.starting_task(task)

            for name in task.dependencies:
                yield from self.run_task(name)

            self.tasks_run.append(name)

            yield events.running_task(task)

            for step in task.steps:
                yield events.running_step(step)

                try:
                    variables = self.resolve_variables(task)
                except LookupError as e:
                    yield events.undefined_variable_error(e.args[0])
                    raise StopTask

                try:
                    step_function = getattr(steps, step.type)
                except AttributeError:
                    yield events.unknown_step_type_error(step)
                    raise StopTask
                else:
                    yield from step_function(self.project, task, step, variables)

            yield events.finished_task(task)
