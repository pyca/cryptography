import select
import subprocess

from . import events


class StopTask(StopIteration):
    pass


def command(project, task, step, variables):
    command = step.args.format(**variables)

    yield events.running_command(command)

    process = subprocess.Popen(command, shell=True,
                               universal_newlines=True, bufsize=1,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

    while True:
        reads = [process.stdout.fileno(), process.stderr.fileno()]
        ret = select.select(reads, [], [])

        for fd in ret[0]:
            if fd == process.stdout.fileno():
                line = process.stdout.readline().strip()
                if line:
                    yield events.command_output('stdout', line)
            if fd == process.stderr.fileno():
                line = process.stderr.readline().strip()
                if line:
                    yield events.command_output('stderr', line)

        if process.poll() != None:
            break

    for line in process.stdout.readlines():
        line = line.strip()
        if line:
            yield events.command_output('stdout', line)

    for line in process.stderr.readlines():
        line = line.strip()
        if line:
            yield events.command_output('stderr', line)

    if process.returncode != 0:
        yield events.command_failed(process.returncode)
        raise StopTask


def help(project, task, step, variables):
    """Run a help step."""

    task_name = step.args or variables['task']

    try:
        task = project.find_task(task_name)
    except NoSuchTaskError as e:
        yield events.task_not_found(task_name, e.similarities)
        raise StopTask

    text = '# {}\n'.format(task.name)
    text += '\n'
    text += task.description
    text += '\n\n'
    text += 'Variables: {}' \
        .format(', '.join(task.variables))

    yield events.help_step_output(text)
