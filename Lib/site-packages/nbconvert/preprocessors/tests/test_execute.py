# coding=utf-8

"""
Module with tests for the execute preprocessor.
"""

# Copyright (c) IPython Development Team.
# Distributed under the terms of the Modified BSD License.

from base64 import b64encode, b64decode
import copy
import glob
import io
import os
import re
import threading
import multiprocessing as mp

import nbformat
import sys
import pytest
import functools

from .base import PreprocessorTestsBase
from ..execute import ExecutePreprocessor, CellExecutionError, executenb, DeadKernelError
from ...exporters.exporter import ResourcesDict

import IPython
from traitlets import TraitError
from nbformat import NotebookNode
from jupyter_client.kernelspec import KernelSpecManager
from nbconvert.filters import strip_ansi
from testpath import modified_env
from ipython_genutils.py3compat import string_types
from pebble import ProcessPool

try:
    from queue import Empty  # Py 3
except ImportError:
    from Queue import Empty  # Py 2
try:
    TimeoutError  # Py 3
except NameError:
    TimeoutError = RuntimeError  # Py 2
try:
    from unittest.mock import MagicMock, patch  # Py 3
except ImportError:
    from mock import MagicMock, patch  # Py 2


PY3 = False
if sys.version_info[0] >= 3:
    PY3 = True

addr_pat = re.compile(r'0x[0-9a-f]{7,9}')
ipython_input_pat = re.compile(r'<ipython-input-\d+-[0-9a-f]+>')
current_dir = os.path.dirname(__file__)
IPY_MAJOR = IPython.version_info[0]


def normalize_base64(b64_text):
    # if it's base64, pass it through b64 decode/encode to avoid
    # equivalent values from being considered unequal
    try:
        return b64encode(b64decode(b64_text.encode('ascii'))).decode('ascii')
    except (ValueError, TypeError):
        return b64_text


def build_preprocessor(opts):
    """Make an instance of a preprocessor"""
    preprocessor = ExecutePreprocessor()
    preprocessor.enabled = True
    for opt in opts:
        setattr(preprocessor, opt, opts[opt])
    # Perform some state setup that should probably be in the init
    preprocessor._display_id_map = {}
    preprocessor.widget_state = {}
    preprocessor.widget_buffers = {}
    return preprocessor


def run_notebook(filename, opts, resources):
    """Loads and runs a notebook, returning both the version prior to
    running it and the version after running it.

    """
    with io.open(filename) as f:
        input_nb = nbformat.read(f, 4)

    preprocessor = build_preprocessor(opts)
    cleaned_input_nb = copy.deepcopy(input_nb)
    for cell in cleaned_input_nb.cells:
        if 'execution_count' in cell:
            del cell['execution_count']
        cell['outputs'] = []

    # Override terminal size to standardise traceback format
    with modified_env({'COLUMNS': '80', 'LINES': '24'}):
        output_nb, _ = preprocessor(cleaned_input_nb, resources)

    return input_nb, output_nb


def prepare_cell_mocks(*messages):
    """
    This function prepares a preprocessor object which has a fake kernel client
    to mock the messages sent over zeromq. The mock kernel client will return
    the messages passed into this wrapper back from `preproc.kc.iopub_channel.get_msg`
    callbacks. It also appends a kernel idle message to the end of messages.

    This allows for testing in with following call expectations:

    @prepare_cell_mocks({
        'msg_type': 'stream',
        'header': {'msg_type': 'stream'},
        'content': {'name': 'stdout', 'text': 'foo'},
    })
    def test_message_foo(self, preprocessor, cell_mock, message_mock):
        preprocessor.kc.iopub_channel.get_msg()
        # =>
        # {
        #     'msg_type': 'stream',
        #     'parent_header': {'msg_id': 'fake_id'},
        #     'header': {'msg_type': 'stream'},
        #     'content': {'name': 'stdout', 'text': 'foo'},
        # }
        preprocessor.kc.iopub_channel.get_msg()
        # =>
        # {
        #     'msg_type': 'status',
        #     'parent_header': {'msg_id': 'fake_id'},
        #     'content': {'execution_state': 'idle'},
        # }
        preprocessor.kc.iopub_channel.get_msg() # => None
        message_mock.call_count # => 3
    """
    parent_id = 'fake_id'
    messages = list(messages)
    # Always terminate messages with an idle to exit the loop
    messages.append({'msg_type': 'status', 'content': {'execution_state': 'idle'}})

    def shell_channel_message_mock():
        # Return the message generator for
        # self.kc.shell_channel.get_msg => {'parent_header': {'msg_id': parent_id}}
        return MagicMock(return_value={'parent_header': {'msg_id': parent_id}})

    def iopub_messages_mock():
        # Return the message generator for
        # self.kc.iopub_channel.get_msg => messages[i]
        return MagicMock(
            side_effect=[
                # Default the parent_header so mocks don't need to include this
                PreprocessorTestsBase.merge_dicts(
                    {'parent_header': {'msg_id': parent_id}}, msg)
                for msg in messages
            ]
        )

    def prepared_wrapper(func):
        @functools.wraps(func)
        def test_mock_wrapper(self):
            """
            This inner function wrapper populates the preprocessor object with
            the fake kernel client. This client has it's iopub and shell
            channels mocked so as to fake the setup handshake and return
            the messages passed into prepare_cell_mocks as the run_cell loop
            processes them.
            """
            cell_mock = NotebookNode(source='"foo" = "bar"', outputs=[])
            preprocessor = build_preprocessor({})
            preprocessor.nb = {'cells': [cell_mock]}

            # self.kc.iopub_channel.get_msg => message_mock.side_effect[i]
            message_mock = iopub_messages_mock()
            preprocessor.kc = MagicMock(
                iopub_channel=MagicMock(get_msg=message_mock),
                shell_channel=MagicMock(get_msg=shell_channel_message_mock()),
                execute=MagicMock(return_value=parent_id)
            )
            preprocessor.parent_id = parent_id
            return func(self, preprocessor, cell_mock, message_mock)
        return test_mock_wrapper
    return prepared_wrapper


def normalize_output(output):
    """
    Normalizes outputs for comparison.
    """
    output = dict(output)
    if 'metadata' in output:
        del output['metadata']
    if 'text' in output:
        output['text'] = re.sub(addr_pat, '<HEXADDR>', output['text'])
    if 'text/plain' in output.get('data', {}):
        output['data']['text/plain'] = \
            re.sub(addr_pat, '<HEXADDR>', output['data']['text/plain'])
    if 'application/vnd.jupyter.widget-view+json' in output.get('data', {}):
        output['data']['application/vnd.jupyter.widget-view+json'] \
            ['model_id'] = '<MODEL_ID>'
    for key, value in output.get('data', {}).items():
        if isinstance(value, string_types):
            if sys.version_info.major == 2:
                value = value.replace('u\'', '\'')
            output['data'][key] = normalize_base64(value)
    if 'traceback' in output:
        tb = [
            re.sub(ipython_input_pat, '<IPY-INPUT>', strip_ansi(line))
            for line in output['traceback']
        ]
        output['traceback'] = tb

    return output


def assert_notebooks_equal(expected, actual):
    expected_cells = expected['cells']
    actual_cells = actual['cells']
    assert len(expected_cells) == len(actual_cells)

    for expected_cell, actual_cell in zip(expected_cells, actual_cells):
        expected_outputs = expected_cell.get('outputs', [])
        actual_outputs = actual_cell.get('outputs', [])
        normalized_expected_outputs = list(map(normalize_output, expected_outputs))
        normalized_actual_outputs = list(map(normalize_output, actual_outputs))
        assert normalized_expected_outputs == normalized_actual_outputs

        expected_execution_count = expected_cell.get('execution_count', None)
        actual_execution_count = actual_cell.get('execution_count', None)
        assert expected_execution_count == actual_execution_count

def notebook_resources():
    """Prepare a notebook resources dictionary for executing test notebooks in the `files` folder."""
    res = ResourcesDict()
    res['metadata'] = ResourcesDict()
    res['metadata']['path'] = os.path.join(current_dir, 'files')
    return res


@pytest.mark.parametrize(
    ["input_name", "opts"],
    [
        ("Clear Output.ipynb", dict(kernel_name="python")),
        ("Empty Cell.ipynb", dict(kernel_name="python")),
        ("Factorials.ipynb", dict(kernel_name="python")),
        ("HelloWorld.ipynb", dict(kernel_name="python")),
        ("Inline Image.ipynb", dict(kernel_name="python")),
        ("Interrupt-IPY6.ipynb", dict(kernel_name="python", timeout=1, interrupt_on_timeout=True, allow_errors=True)) if IPY_MAJOR < 7 else
            ("Interrupt.ipynb", dict(kernel_name="python", timeout=1, interrupt_on_timeout=True, allow_errors=True)),
        ("JupyterWidgets.ipynb", dict(kernel_name="python")),
        ("Skip Exceptions with Cell Tags-IPY6.ipynb", dict(kernel_name="python")) if IPY_MAJOR < 7 else
            ("Skip Exceptions with Cell Tags.ipynb", dict(kernel_name="python")),
        ("Skip Exceptions-IPY6.ipynb", dict(kernel_name="python", allow_errors=True)) if IPY_MAJOR < 7 else
            ("Skip Exceptions.ipynb", dict(kernel_name="python", allow_errors=True)),
        ("SVG.ipynb", dict(kernel_name="python")),
        ("Unicode.ipynb", dict(kernel_name="python")),
        ("UnicodePy3.ipynb", dict(kernel_name="python")),
        ("update-display-id.ipynb", dict(kernel_name="python")),
        ("Check History in Memory.ipynb", dict(kernel_name="python")),
    ]
)
def test_run_all_notebooks(input_name, opts):
    """Runs a series of test notebooks and compares them to their actual output"""
    input_file = os.path.join(current_dir, 'files', input_name)
    input_nb, output_nb = run_notebook(input_file, opts, notebook_resources())
    assert_notebooks_equal(input_nb, output_nb)

@pytest.mark.skipif(not PY3,
                    reason = "Not tested for Python 2")
def test_parallel_notebooks(capfd, tmpdir):
    """Two notebooks should be able to be run simultaneously without problems.

    The two notebooks spawned here use the filesystem to check that the other notebook
    wrote to the filesystem."""

    opts = dict(kernel_name="python")
    input_name = "Parallel Execute {label}.ipynb"
    input_file = os.path.join(current_dir, "files", input_name)
    res = notebook_resources()

    with modified_env({"NBEXECUTE_TEST_PARALLEL_TMPDIR": str(tmpdir)}):
        threads = [
            threading.Thread(
                target=run_notebook,
                args=(
                    input_file.format(label=label),
                    opts,
                    res,
                ),
            )
            for label in ("A", "B")
        ]
        [t.start() for t in threads]
        [t.join(timeout=2) for t in threads]

    captured = capfd.readouterr()
    assert captured.err == ""

@pytest.mark.skipif(not PY3,
                    reason = "Not tested for Python 2")
def test_many_parallel_notebooks(capfd):
    """Ensure that when many IPython kernels are run in parallel, nothing awful happens.

    Specifically, many IPython kernels when run simultaneously would enocunter errors
    due to using the same SQLite history database.
    """
    opts = dict(kernel_name="python", timeout=5)
    input_name = "HelloWorld.ipynb"
    input_file = os.path.join(current_dir, "files", input_name)
    res = PreprocessorTestsBase().build_resources()
    res["metadata"]["path"] = os.path.join(current_dir, "files")

    # run once, to trigger creating the original context
    run_notebook(input_file, opts, res)

    with ProcessPool(max_workers=4) as pool:
        futures = [
            # Travis needs a lot more time even though 10s is enough on most dev machines
            pool.schedule(run_notebook, args=(input_file, opts, res), timeout=30)
            for i in range(0, 8)
        ]
        for index, future in enumerate(futures):
            future.result()

    captured = capfd.readouterr()
    assert captured.err == ""

class TestExecute(PreprocessorTestsBase):
    """Contains test functions for execute.py"""
    maxDiff = None

    def test_constructor(self):
        """Can a ExecutePreprocessor be constructed?"""
        build_preprocessor({})

    def test_populate_language_info(self):
        preprocessor = build_preprocessor(opts=dict(kernel_name="python"))
        nb = nbformat.v4.new_notebook()  # Certainly has no language_info.
        nb, _ = preprocessor.preprocess(nb, resources={})
        assert 'language_info' in nb.metadata

    def test_empty_path(self):
        """Can the kernel be started when the path is empty?"""
        filename = os.path.join(current_dir, 'files', 'HelloWorld.ipynb')
        res = self.build_resources()
        res['metadata']['path'] = ''
        input_nb, output_nb = run_notebook(filename, {}, res)
        assert_notebooks_equal(input_nb, output_nb)

    @pytest.mark.xfail("python3" not in KernelSpecManager().find_kernel_specs(),
                        reason="requires a python3 kernelspec")
    def test_empty_kernel_name(self):
        """Can kernel in nb metadata be found when an empty string is passed?

        Note: this pattern should be discouraged in practice.
        Passing in no kernel_name to ExecutePreprocessor is recommended instead.
        """
        filename = os.path.join(current_dir, 'files', 'UnicodePy3.ipynb')
        res = self.build_resources()
        input_nb, output_nb = run_notebook(filename, {"kernel_name": ""}, res)
        assert_notebooks_equal(input_nb, output_nb)
        with pytest.raises(TraitError):
            input_nb, output_nb = run_notebook(filename, {"kernel_name": None}, res)

    def test_disable_stdin(self):
        """Test disabling standard input"""
        filename = os.path.join(current_dir, 'files', 'Disable Stdin.ipynb')
        res = self.build_resources()
        res['metadata']['path'] = os.path.dirname(filename)
        input_nb, output_nb = run_notebook(filename, dict(allow_errors=True), res)

        # We need to special-case this particular notebook, because the
        # traceback contains machine-specific stuff like where IPython
        # is installed. It is sufficient here to just check that an error
        # was thrown, and that it was a StdinNotImplementedError
        self.assertEqual(len(output_nb['cells']), 1)
        self.assertEqual(len(output_nb['cells'][0]['outputs']), 1)
        output = output_nb['cells'][0]['outputs'][0]
        self.assertEqual(output['output_type'], 'error')
        self.assertEqual(output['ename'], 'StdinNotImplementedError')
        self.assertEqual(output['evalue'], 'raw_input was called, but this frontend does not support input requests.')

    def test_timeout(self):
        """Check that an error is raised when a computation times out"""
        filename = os.path.join(current_dir, 'files', 'Interrupt.ipynb')
        res = self.build_resources()
        res['metadata']['path'] = os.path.dirname(filename)

        with pytest.raises(TimeoutError):
            run_notebook(filename, dict(timeout=1), res)

    def test_timeout_func(self):
        """Check that an error is raised when a computation times out"""
        filename = os.path.join(current_dir, 'files', 'Interrupt.ipynb')
        res = self.build_resources()
        res['metadata']['path'] = os.path.dirname(filename)

        def timeout_func(source):
            return 10

        with pytest.raises(TimeoutError):
            run_notebook(filename, dict(timeout_func=timeout_func), res)

    def test_kernel_death(self):
        """Check that an error is raised when the kernel is_alive is false"""
        filename = os.path.join(current_dir, 'files', 'Interrupt.ipynb')
        with io.open(filename, 'r') as f:
            input_nb = nbformat.read(f, 4)
        res = self.build_resources()
        res['metadata']['path'] = os.path.dirname(filename)

        preprocessor = build_preprocessor({"timeout": 5})

        try:
            input_nb, output_nb = preprocessor(input_nb, {})
        except TimeoutError:
            pass
        km, kc = preprocessor.start_new_kernel()

        with patch.object(km, "is_alive") as alive_mock:
            alive_mock.return_value = False
            with pytest.raises(DeadKernelError):
                input_nb, output_nb = preprocessor.preprocess(input_nb, {}, km=km)


    def test_allow_errors(self):
        """
        Check that conversion halts if ``allow_errors`` is False.
        """
        filename = os.path.join(current_dir, 'files', 'Skip Exceptions.ipynb')
        res = self.build_resources()
        res['metadata']['path'] = os.path.dirname(filename)
        with pytest.raises(CellExecutionError) as exc:
            run_notebook(filename, dict(allow_errors=False), res)
            self.assertIsInstance(str(exc.value), str)
            if sys.version_info >= (3, 0):
                assert u"# üñîçø∂é" in str(exc.value)
            else:
                assert u"# üñîçø∂é".encode('utf8', 'replace') in str(exc.value)

    def test_force_raise_errors(self):
        """
        Check that conversion halts if the ``force_raise_errors`` traitlet on
        ExecutePreprocessor is set to True.
        """
        filename = os.path.join(current_dir, 'files',
                                'Skip Exceptions with Cell Tags.ipynb')
        res = self.build_resources()
        res['metadata']['path'] = os.path.dirname(filename)
        with pytest.raises(CellExecutionError) as exc:
            run_notebook(filename, dict(force_raise_errors=True), res)
            self.assertIsInstance(str(exc.value), str)
            if sys.version_info >= (3, 0):
                assert u"# üñîçø∂é" in str(exc.value)
            else:
                assert u"# üñîçø∂é".encode('utf8', 'replace') in str(exc.value)

    def test_custom_kernel_manager(self):
        from .fake_kernelmanager import FakeCustomKernelManager

        filename = os.path.join(current_dir, 'files', 'HelloWorld.ipynb')

        with io.open(filename) as f:
            input_nb = nbformat.read(f, 4)

        preprocessor = build_preprocessor({
            'kernel_manager_class': FakeCustomKernelManager
        })

        cleaned_input_nb = copy.deepcopy(input_nb)
        for cell in cleaned_input_nb.cells:
            if 'execution_count' in cell:
                del cell['execution_count']
            cell['outputs'] = []

        # Override terminal size to standardise traceback format
        with modified_env({'COLUMNS': '80', 'LINES': '24'}):
            output_nb, _ = preprocessor(cleaned_input_nb,
                                        self.build_resources())

        expected = FakeCustomKernelManager.expected_methods.items()

        for method, call_count in expected:
            self.assertNotEqual(call_count, 0, '{} was called'.format(method))

    def test_process_message_wrapper(self):
        outputs = []

        class WrappedPreProc(ExecutePreprocessor):
            def process_message(self, msg, cell, cell_index):
                result = super(WrappedPreProc, self).process_message(msg, cell, cell_index)
                if result:
                    outputs.append(result)
                return result

        current_dir = os.path.dirname(__file__)
        filename = os.path.join(current_dir, 'files', 'HelloWorld.ipynb')

        with io.open(filename) as f:
            input_nb = nbformat.read(f, 4)

        original = copy.deepcopy(input_nb)
        wpp = WrappedPreProc()
        executed = wpp.preprocess(input_nb, {})[0]
        assert outputs == [
            {'name': 'stdout', 'output_type': 'stream', 'text': 'Hello World\n'}
        ]
        assert_notebooks_equal(original, executed)

    def test_execute_function(self):
        # Test the executenb() convenience API
        filename = os.path.join(current_dir, 'files', 'HelloWorld.ipynb')

        with io.open(filename) as f:
            input_nb = nbformat.read(f, 4)

        original = copy.deepcopy(input_nb)
        executed = executenb(original, os.path.dirname(filename))
        assert_notebooks_equal(original, executed)

    def test_widgets(self):
        """Runs a test notebook with widgets and checks the widget state is saved."""
        input_file = os.path.join(current_dir, 'files', 'JupyterWidgets.ipynb')
        opts = dict(kernel_name="python")
        res = self.build_resources()
        res['metadata']['path'] = os.path.dirname(input_file)
        input_nb, output_nb = run_notebook(input_file, opts, res)

        output_data = [
            output.get('data', {})
            for cell in output_nb['cells']
            for output in cell['outputs']
        ]

        model_ids = [
            data['application/vnd.jupyter.widget-view+json']['model_id']
            for data in output_data
            if 'application/vnd.jupyter.widget-view+json' in data
        ]

        wdata = output_nb['metadata']['widgets'] \
                ['application/vnd.jupyter.widget-state+json']
        for k in model_ids:
            d = wdata['state'][k]
            assert 'model_name' in d
            assert 'model_module' in d
            assert 'state' in d
        assert 'version_major' in wdata
        assert 'version_minor' in wdata


class TestRunCell(PreprocessorTestsBase):
    """Contains test functions for ExecutePreprocessor.run_cell"""

    @prepare_cell_mocks()
    def test_idle_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # Just the exit message should be fetched
        assert message_mock.call_count == 1
        # Ensure no outputs were generated
        assert cell_mock.outputs == []

    @prepare_cell_mocks({
        'msg_type': 'stream',
        'header': {'msg_type': 'execute_reply'},
        'parent_header': {'msg_id': 'wrong_parent'},
        'content': {'name': 'stdout', 'text': 'foo'}
    })
    def test_message_for_wrong_parent(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # An ignored stream followed by an idle
        assert message_mock.call_count == 2
        # Ensure no output was written
        assert cell_mock.outputs == []

    @prepare_cell_mocks({
        'msg_type': 'status',
        'header': {'msg_type': 'status'},
        'content': {'execution_state': 'busy'}
    })
    def test_busy_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # One busy message, followed by an idle
        assert message_mock.call_count == 2
        # Ensure no outputs were generated
        assert cell_mock.outputs == []

    @prepare_cell_mocks({
        'msg_type': 'stream',
        'header': {'msg_type': 'stream'},
        'content': {'name': 'stdout', 'text': 'foo'},
    }, {
        'msg_type': 'stream',
        'header': {'msg_type': 'stream'},
        'content': {'name': 'stderr', 'text': 'bar'}
    })
    def test_deadline_exec_reply(self, preprocessor, cell_mock, message_mock):
        # exec_reply is never received, so we expect to hit the timeout.
        preprocessor.kc.shell_channel.get_msg = MagicMock(side_effect=Empty())
        preprocessor.timeout = 1

        with pytest.raises(TimeoutError):
            preprocessor.run_cell(cell_mock)

        assert message_mock.call_count == 3
        # Ensure the output was captured
        self.assertListEqual(cell_mock.outputs, [
            {'output_type': 'stream', 'name': 'stdout', 'text': 'foo'},
            {'output_type': 'stream', 'name': 'stderr', 'text': 'bar'}
        ])

    @prepare_cell_mocks()
    def test_deadline_iopub(self, preprocessor, cell_mock, message_mock):
        # The shell_channel will complete, so we expect only to hit the iopub timeout.
        message_mock.side_effect = Empty()
        preprocessor.raise_on_iopub_timeout = True

        with pytest.raises(TimeoutError):
            preprocessor.run_cell(cell_mock)

    @prepare_cell_mocks({
        'msg_type': 'stream',
        'header': {'msg_type': 'stream'},
        'content': {'name': 'stdout', 'text': 'foo'},
    }, {
        'msg_type': 'stream',
        'header': {'msg_type': 'stream'},
        'content': {'name': 'stderr', 'text': 'bar'}
    })
    def test_eventual_deadline_iopub(self, preprocessor, cell_mock, message_mock):
        # Process a few messages before raising a timeout from iopub
        message_mock.side_effect = list(message_mock.side_effect)[:-1] + [Empty()]
        preprocessor.kc.shell_channel.get_msg = MagicMock(
            return_value={'parent_header': {'msg_id': preprocessor.parent_id}})
        preprocessor.raise_on_iopub_timeout = True

        with pytest.raises(TimeoutError):
            preprocessor.run_cell(cell_mock)

        assert message_mock.call_count == 3
        # Ensure the output was captured
        self.assertListEqual(cell_mock.outputs, [
            {'output_type': 'stream', 'name': 'stdout', 'text': 'foo'},
            {'output_type': 'stream', 'name': 'stderr', 'text': 'bar'}
        ])

    @prepare_cell_mocks({
        'msg_type': 'execute_input',
        'header': {'msg_type': 'execute_input'},
        'content': {}
    })
    def test_execute_input_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # One ignored execute_input, followed by an idle
        assert message_mock.call_count == 2
        # Ensure no outputs were generated
        assert cell_mock.outputs == []

    @prepare_cell_mocks({
        'msg_type': 'stream',
        'header': {'msg_type': 'stream'},
        'content': {'name': 'stdout', 'text': 'foo'},
    }, {
        'msg_type': 'stream',
        'header': {'msg_type': 'stream'},
        'content': {'name': 'stderr', 'text': 'bar'}
    })
    def test_stream_messages(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # An stdout then stderr stream followed by an idle
        assert message_mock.call_count == 3
        # Ensure the output was captured
        self.assertListEqual(cell_mock.outputs, [
            {'output_type': 'stream', 'name': 'stdout', 'text': 'foo'},
            {'output_type': 'stream', 'name': 'stderr', 'text': 'bar'}
        ])

    @prepare_cell_mocks({
        'msg_type': 'stream',
        'header': {'msg_type': 'execute_reply'},
        'content': {'name': 'stdout', 'text': 'foo'}
    }, {
        'msg_type': 'clear_output',
        'header': {'msg_type': 'clear_output'},
        'content': {}
    })
    def test_clear_output_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # A stream, followed by a clear, and then an idle
        assert message_mock.call_count == 3
        # Ensure the output was cleared
        assert cell_mock.outputs == []

    @prepare_cell_mocks({
        'msg_type': 'stream',
        'header': {'msg_type': 'stream'},
        'content': {'name': 'stdout', 'text': 'foo'}
    }, {
        'msg_type': 'clear_output',
        'header': {'msg_type': 'clear_output'},
        'content': {'wait': True}
    })
    def test_clear_output_wait_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # A stream, followed by a clear, and then an idle
        assert message_mock.call_count == 3
        # Should be true without another message to trigger the clear
        self.assertTrue(preprocessor.clear_before_next_output)
        # Ensure the output wasn't cleared yet
        assert cell_mock.outputs == [
            {'output_type': 'stream', 'name': 'stdout', 'text': 'foo'}
        ]

    @prepare_cell_mocks({
        'msg_type': 'stream',
        'header': {'msg_type': 'stream'},
        'content': {'name': 'stdout', 'text': 'foo'}
    }, {
        'msg_type': 'clear_output',
        'header': {'msg_type': 'clear_output'},
        'content': {'wait': True}
    }, {
        'msg_type': 'stream',
        'header': {'msg_type': 'stream'},
        'content': {'name': 'stderr', 'text': 'bar'}
    })
    def test_clear_output_wait_then_message_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # An stdout stream, followed by a wait clear, an stderr stream, and then an idle
        assert message_mock.call_count == 4
        # Should be false after the stderr message
        assert not preprocessor.clear_before_next_output
        # Ensure the output wasn't cleared yet
        assert cell_mock.outputs == [
            {'output_type': 'stream', 'name': 'stderr', 'text': 'bar'}
        ]

    @prepare_cell_mocks({
        'msg_type': 'stream',
        'header': {'msg_type': 'stream'},
        'content': {'name': 'stdout', 'text': 'foo'}
    }, {
        'msg_type': 'clear_output',
        'header': {'msg_type': 'clear_output'},
        'content': {'wait': True}
    }, {
        'msg_type': 'update_display_data',
        'header': {'msg_type': 'update_display_data'},
        'content': {'metadata': {'metafoo': 'metabar'}, 'data': {'foo': 'bar'}}
    })
    def test_clear_output_wait_then_update_display_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # An stdout stream, followed by a wait clear, an stderr stream, and then an idle
        assert message_mock.call_count == 4
        # Should be false after the stderr message
        assert preprocessor.clear_before_next_output
        # Ensure the output wasn't cleared yet because update_display doesn't add outputs
        assert cell_mock.outputs == [
            {'output_type': 'stream', 'name': 'stdout', 'text': 'foo'}
        ]

    @prepare_cell_mocks({
        'msg_type': 'execute_reply',
        'header': {'msg_type': 'execute_reply'},
        'content': {'execution_count': 42}
    })
    def test_execution_count_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # An execution count followed by an idle
        assert message_mock.call_count == 2
        assert cell_mock.execution_count == 42
        # Ensure no outputs were generated
        assert cell_mock.outputs == []

    @prepare_cell_mocks({
        'msg_type': 'stream',
        'header': {'msg_type': 'stream'},
        'content': {'execution_count': 42, 'name': 'stdout', 'text': 'foo'}
    })
    def test_execution_count_with_stream_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # An execution count followed by an idle
        assert message_mock.call_count == 2
        assert cell_mock.execution_count == 42
        # Should also consume the message stream
        assert cell_mock.outputs == [
            {'output_type': 'stream', 'name': 'stdout', 'text': 'foo'}
        ]

    @prepare_cell_mocks({
        'msg_type': 'comm',
        'header': {'msg_type': 'comm'},
        'content': {
            'comm_id': 'foobar',
            'data': {'state': {'foo': 'bar'}}
        }
    })
    def test_widget_comm_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # A comm message without buffer info followed by an idle
        assert message_mock.call_count == 2
        self.assertEqual(preprocessor.widget_state, {'foobar': {'foo': 'bar'}})
        # Buffers should still be empty
        assert not preprocessor.widget_buffers
        # Ensure no outputs were generated
        assert cell_mock.outputs == []

    @prepare_cell_mocks({
        'msg_type': 'comm',
        'header': {'msg_type': 'comm'},
        'buffers': [b'123'],
        'content': {
            'comm_id': 'foobar',
            'data': {
                'state': {'foo': 'bar'},
                'buffer_paths': ['path']
            }
        }
    })
    def test_widget_comm_buffer_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # A comm message with buffer info followed by an idle
        assert message_mock.call_count == 2
        assert preprocessor.widget_state == {'foobar': {'foo': 'bar'}}
        assert preprocessor.widget_buffers == {
            'foobar': [{'data': 'MTIz', 'encoding': 'base64', 'path': 'path'}]
        }
        # Ensure no outputs were generated
        assert cell_mock.outputs == []

    @prepare_cell_mocks({
        'msg_type': 'comm',
        'header': {'msg_type': 'comm'},
        'content': {
            'comm_id': 'foobar',
            # No 'state'
            'data': {'foo': 'bar'}
        }
    })
    def test_unknown_comm_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # An unknown comm message followed by an idle
        assert message_mock.call_count == 2
        # Widget states should be empty as the message has the wrong shape
        assert not preprocessor.widget_state
        assert not preprocessor.widget_buffers
        # Ensure no outputs were generated
        assert cell_mock.outputs == []

    @prepare_cell_mocks({
        'msg_type': 'execute_result',
        'header': {'msg_type': 'execute_result'},
        'content': {
            'metadata': {'metafoo': 'metabar'},
            'data': {'foo': 'bar'},
            'execution_count': 42
        }
    })
    def test_execute_result_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # An execute followed by an idle
        assert message_mock.call_count == 2
        assert cell_mock.execution_count == 42
        # Should generate an associated message
        assert cell_mock.outputs == [{
            'output_type': 'execute_result',
            'metadata': {'metafoo': 'metabar'},
            'data': {'foo': 'bar'},
            'execution_count': 42
        }]
        # No display id was provided
        assert not preprocessor._display_id_map

    @prepare_cell_mocks({
        'msg_type': 'execute_result',
        'header': {'msg_type': 'execute_result'},
        'content': {
            'transient': {'display_id': 'foobar'},
            'metadata': {'metafoo': 'metabar'},
            'data': {'foo': 'bar'},
            'execution_count': 42
        }
    })
    def test_execute_result_with_display_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # An execute followed by an idle
        assert message_mock.call_count == 2
        assert cell_mock.execution_count == 42
        # Should generate an associated message
        assert cell_mock.outputs == [{
            'output_type': 'execute_result',
            'metadata': {'metafoo': 'metabar'},
            'data': {'foo': 'bar'},
            'execution_count': 42
        }]
        assert 'foobar' in preprocessor._display_id_map

    @prepare_cell_mocks({
        'msg_type': 'display_data',
        'header': {'msg_type': 'display_data'},
        'content': {'metadata': {'metafoo': 'metabar'}, 'data': {'foo': 'bar'}}
    })
    def test_display_data_without_id_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # A display followed by an idle
        assert message_mock.call_count == 2
        # Should generate an associated message
        assert cell_mock.outputs == [{
            'output_type': 'display_data',
            'metadata': {'metafoo': 'metabar'},
            'data': {'foo': 'bar'}
        }]
        # No display id was provided
        assert not preprocessor._display_id_map

    @prepare_cell_mocks({
        'msg_type': 'display_data',
        'header': {'msg_type': 'display_data'},
        'content': {
            'transient': {'display_id': 'foobar'},
            'metadata': {'metafoo': 'metabar'},
            'data': {'foo': 'bar'}
        }
    })
    def test_display_data_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # A display followed by an idle
        assert message_mock.call_count == 2
        # Should generate an associated message
        assert cell_mock.outputs == [{
            'output_type': 'display_data',
            'metadata': {'metafoo': 'metabar'},
            'data': {'foo': 'bar'}
        }]
        assert 'foobar' in preprocessor._display_id_map

    @prepare_cell_mocks({
        'msg_type': 'display_data',
        'header': {'msg_type': 'display_data'},
        'content': {
            'transient': {'display_id': 'foobar'},
            'metadata': {'metafoo': 'metabar'},
            'data': {'foo': 'bar'}
        }
    }, {
        'msg_type': 'display_data',
        'header': {'msg_type': 'display_data'},
        'content': {
            'transient': {'display_id': 'foobar_other'},
            'metadata': {'metafoo_other': 'metabar_other'},
            'data': {'foo': 'bar_other'}
        }
    }, {
        'msg_type': 'display_data',
        'header': {'msg_type': 'display_data'},
        'content': {
            'transient': {'display_id': 'foobar'},
            'metadata': {'metafoo2': 'metabar2'},
            'data': {'foo': 'bar2', 'baz': 'foobarbaz'}
        }
    })
    def test_display_data_same_id_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # A display followed by an idle
        assert message_mock.call_count == 4
        # Original output should be manipulated and a copy of the second now
        assert cell_mock.outputs == [{
            'output_type': 'display_data',
            'metadata': {'metafoo2': 'metabar2'},
            'data': {'foo': 'bar2', 'baz': 'foobarbaz'}
        }, {
            'output_type': 'display_data',
            'metadata': {'metafoo_other': 'metabar_other'},
            'data': {'foo': 'bar_other'}
        }, {
            'output_type': 'display_data',
            'metadata': {'metafoo2': 'metabar2'},
            'data': {'foo': 'bar2', 'baz': 'foobarbaz'}
        }]
        assert 'foobar' in preprocessor._display_id_map

    @prepare_cell_mocks({
        'msg_type': 'update_display_data',
        'header': {'msg_type': 'update_display_data'},
        'content': {'metadata': {'metafoo': 'metabar'}, 'data': {'foo': 'bar'}}
    })
    def test_update_display_data_without_id_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # An update followed by an idle
        assert message_mock.call_count == 2
        # Display updates don't create any outputs
        assert cell_mock.outputs == []
        # No display id was provided
        assert not preprocessor._display_id_map

    @prepare_cell_mocks({
        'msg_type': 'display_data',
        'header': {'msg_type': 'display_data'},
        'content': {
            'transient': {'display_id': 'foobar'},
            'metadata': {'metafoo2': 'metabar2'},
            'data': {'foo': 'bar2', 'baz': 'foobarbaz'}
        }
    }, {
        'msg_type': 'update_display_data',
        'header': {'msg_type': 'update_display_data'},
        'content': {
            'transient': {'display_id': 'foobar2'},
            'metadata': {'metafoo2': 'metabar2'},
            'data': {'foo': 'bar2', 'baz': 'foobarbaz'}
        }
    })
    def test_update_display_data_mismatch_id_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # An update followed by an idle
        assert message_mock.call_count == 3
        # Display updates don't create any outputs
        assert cell_mock.outputs == [{
            'output_type': 'display_data',
            'metadata': {'metafoo2': 'metabar2'},
            'data': {'foo': 'bar2', 'baz': 'foobarbaz'}
        }]
        assert 'foobar' in preprocessor._display_id_map

    @prepare_cell_mocks({
        'msg_type': 'display_data',
        'header': {'msg_type': 'display_data'},
        'content': {
            'transient': {'display_id': 'foobar'},
            'metadata': {'metafoo': 'metabar'},
            'data': {'foo': 'bar'}
        }
    }, {
        'msg_type': 'update_display_data',
        'header': {'msg_type': 'update_display_data'},
        'content': {
            'transient': {'display_id': 'foobar'},
            'metadata': {'metafoo2': 'metabar2'},
            'data': {'foo': 'bar2', 'baz': 'foobarbaz'}
        }
    })
    def test_update_display_data_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # A display followed by an update then an idle
        assert message_mock.call_count == 3
        # Original output should be manipulated
        assert cell_mock.outputs == [{
            'output_type': 'display_data',
            'metadata': {'metafoo2': 'metabar2'},
            'data': {'foo': 'bar2', 'baz': 'foobarbaz'}
        }]
        assert 'foobar' in preprocessor._display_id_map

    @prepare_cell_mocks({
        'msg_type': 'error',
        'header': {'msg_type': 'error'},
        'content': {'ename': 'foo', 'evalue': 'bar', 'traceback': ['Boom']}
    })
    def test_error_message(self, preprocessor, cell_mock, message_mock):
        preprocessor.run_cell(cell_mock)
        # An error followed by an idle
        assert message_mock.call_count == 2
        # Should also consume the message stream
        assert cell_mock.outputs == [{
            'output_type': 'error',
            'ename': 'foo',
            'evalue': 'bar',
            'traceback': ['Boom']
        }]
