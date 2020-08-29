"""Module containing a preprocessor that executes the code cells
and updates outputs"""

# Copyright (c) IPython Development Team.
# Distributed under the terms of the Modified BSD License.
import base64
from textwrap import dedent
from contextlib import contextmanager
try:
    from time import monotonic # Py 3
except ImportError:
    from time import time as monotonic # Py 2

try:
    from queue import Empty  # Py 3
except ImportError:
    from Queue import Empty  # Py 2

try:
    TimeoutError  # Py 3
except NameError:
    TimeoutError = RuntimeError  # Py 2

from traitlets import List, Unicode, Bool, Enum, Any, Type, Dict, Integer, default

from nbformat.v4 import output_from_msg

from .base import Preprocessor
from ..utils.exceptions import ConversionException

class DeadKernelError(RuntimeError):
    pass

class CellExecutionComplete(Exception):
    """
    Used as a control signal for cell execution across run_cell and
    process_message function calls. Raised when all execution requests
    are completed and no further messages are expected from the kernel
    over zeromq channels.
    """
    pass

class CellExecutionError(ConversionException):
    """
    Custom exception to propagate exceptions that are raised during
    notebook execution to the caller. This is mostly useful when
    using nbconvert as a library, since it allows to deal with
    failures gracefully.
    """
    def __init__(self, traceback):
        super(CellExecutionError, self).__init__(traceback)
        self.traceback = traceback

    def __str__(self):
        s = self.__unicode__()
        if not isinstance(s, str):
            s = s.encode('utf8', 'replace')
        return s

    def __unicode__(self):
        return self.traceback

    @classmethod
    def from_cell_and_msg(cls, cell, msg):
        """Instantiate from a code cell object and a message contents
        (message is either execute_reply or error)
        """
        tb = '\n'.join(msg.get('traceback', []))
        return cls(exec_err_msg.format(cell=cell, traceback=tb,
                                       ename=msg.get('ename', '<Error>'),
                                       evalue=msg.get('evalue', '')
                                      ))

exec_err_msg = u"""\
An error occurred while executing the following cell:
------------------
{cell.source}
------------------

{traceback}
{ename}: {evalue}
"""

class ExecutePreprocessor(Preprocessor):
    """
    Executes all the cells in a notebook
    """

    timeout = Integer(30, allow_none=True,
        help=dedent(
            """
            The time to wait (in seconds) for output from executions.
            If a cell execution takes longer, an exception (TimeoutError
            on python 3+, RuntimeError on python 2) is raised.

            `None` or `-1` will disable the timeout. If `timeout_func` is set,
            it overrides `timeout`.
            """
        )
    ).tag(config=True)

    timeout_func = Any(
        default_value=None,
        allow_none=True,
        help=dedent(
            """
            A callable which, when given the cell source as input,
            returns the time to wait (in seconds) for output from cell
            executions. If a cell execution takes longer, an exception
            (TimeoutError on python 3+, RuntimeError on python 2) is
            raised.

            Returning `None` or `-1` will disable the timeout for the cell.
            Not setting `timeout_func` will cause the preprocessor to
            default to using the `timeout` trait for all cells. The
            `timeout_func` trait overrides `timeout` if it is not `None`.
            """
        )
    ).tag(config=True)

    interrupt_on_timeout = Bool(False,
        help=dedent(
            """
            If execution of a cell times out, interrupt the kernel and
            continue executing other cells rather than throwing an error and
            stopping.
            """
        )
    ).tag(config=True)

    startup_timeout = Integer(60,
        help=dedent(
            """
            The time to wait (in seconds) for the kernel to start.
            If kernel startup takes longer, a RuntimeError is
            raised.
            """
        )
    ).tag(config=True)

    allow_errors = Bool(False,
        help=dedent(
            """
            If `False` (default), when a cell raises an error the
            execution is stopped and a `CellExecutionError`
            is raised.
            If `True`, execution errors are ignored and the execution
            is continued until the end of the notebook. Output from
            exceptions is included in the cell output in both cases.
            """
        )
    ).tag(config=True)

    force_raise_errors = Bool(False,
        help=dedent(
            """
            If False (default), errors from executing the notebook can be
            allowed with a `raises-exception` tag on a single cell, or the
            `allow_errors` configurable option for all cells. An allowed error
            will be recorded in notebook output, and execution will continue.
            If an error occurs when it is not explicitly allowed, a
            `CellExecutionError` will be raised.
            If True, `CellExecutionError` will be raised for any error that occurs
            while executing the notebook. This overrides both the
            `allow_errors` option and the `raises-exception` cell tag.
            """
        )
    ).tag(config=True)

    extra_arguments = List(Unicode())

    kernel_name = Unicode('',
        help=dedent(
            """
            Name of kernel to use to execute the cells.
            If not set, use the kernel_spec embedded in the notebook.
            """
        )
    ).tag(config=True)

    raise_on_iopub_timeout = Bool(False,
        help=dedent(
            """
            If `False` (default), then the kernel will continue waiting for
            iopub messages until it receives a kernel idle message, or until a
            timeout occurs, at which point the currently executing cell will be
            skipped. If `True`, then an error will be raised after the first
            timeout. This option generally does not need to be used, but may be
            useful in contexts where there is the possibility of executing
            notebooks with memory-consuming infinite loops.
            """
            )
    ).tag(config=True)

    store_widget_state = Bool(True,
        help=dedent(
            """
            If `True` (default), then the state of the Jupyter widgets created
            at the kernel will be stored in the metadata of the notebook.
            """
            )
    ).tag(config=True)

    iopub_timeout = Integer(4, allow_none=False,
        help=dedent(
            """
            The time to wait (in seconds) for IOPub output. This generally
            doesn't need to be set, but on some slow networks (such as CI
            systems) the default timeout might not be long enough to get all
            messages.
            """
        )
    ).tag(config=True)

    shutdown_kernel = Enum(['graceful', 'immediate'],
        default_value='graceful',
        help=dedent(
            """
            If `graceful` (default), then the kernel is given time to clean
            up after executing all cells, e.g., to execute its `atexit` hooks.
            If `immediate`, then the kernel is signaled to immediately
            terminate.
            """
            )
    ).tag(config=True)

    ipython_hist_file = Unicode(
        default_value=':memory:',
        help="""Path to file to use for SQLite history database for an IPython kernel.
        
        The specific value `:memory:` (including the colon
        at both end but not the back ticks), avoids creating a history file. Otherwise, IPython
        will create a history file for each kernel. 
        
        When running kernels simultaneously (e.g. via multiprocessing) saving history a single
        SQLite file can result in database errors, so using `:memory:` is recommended in non-interactive
        contexts.
        
        """).tag(config=True)

    kernel_manager_class = Type(
        config=True,
        help='The kernel manager class to use.'
    )
    @default('kernel_manager_class')
    def _kernel_manager_class_default(self):
        """Use a dynamic default to avoid importing jupyter_client at startup"""
        try:
            from jupyter_client import KernelManager
        except ImportError:
            raise ImportError("`nbconvert --execute` requires the jupyter_client package: `pip install jupyter_client`")
        return KernelManager

    _display_id_map = Dict(
        help=dedent(
              """
              mapping of locations of outputs with a given display_id
              tracks cell index and output index within cell.outputs for
              each appearance of the display_id
              {
                   'display_id': {
                  cell_idx: [output_idx,]
                   }
              }
              """))

    def start_new_kernel(self, **kwargs):
        """Creates a new kernel manager and kernel client.

        Parameters
        ----------
        kwargs :
            Any options for `self.kernel_manager_class.start_kernel()`. Because
            that defaults to KernelManager, this will likely include options
            accepted by `KernelManager.start_kernel()``, which includes `cwd`.

        Returns
        -------
        km : KernelManager
            A kernel manager as created by self.kernel_manager_class.
        kc : KernelClient
            Kernel client as created by the kernel manager `km`.
        """
        if not self.kernel_name:
            self.kernel_name = self.nb.metadata.get(
                'kernelspec', {}).get('name', 'python')
        km = self.kernel_manager_class(kernel_name=self.kernel_name,
                                       config=self.config)
        if km.ipykernel and self.ipython_hist_file:
            self.extra_arguments += ['--HistoryManager.hist_file={}'.format(self.ipython_hist_file)]
        km.start_kernel(extra_arguments=self.extra_arguments, **kwargs)

        kc = km.client()
        kc.start_channels()
        try:
            kc.wait_for_ready(timeout=self.startup_timeout)
        except RuntimeError:
            kc.stop_channels()
            km.shutdown_kernel()
            raise
        kc.allow_stdin = False
        return km, kc

    @contextmanager
    def setup_preprocessor(self, nb, resources, km=None, **kwargs):
        """
        Context manager for setting up the class to execute a notebook.

        The assigns `nb` to `self.nb` where it will be modified in-place. It also creates
        and assigns the Kernel Manager (`self.km`) and Kernel Client(`self.kc`).

        It is intended to yield to a block that will execute codeself.

        When control returns from the yield it stops the client's zmq channels, shuts
        down the kernel, and removes the now unused attributes.

        Parameters
        ----------
        nb : NotebookNode
            Notebook being executed.
        resources : dictionary
            Additional resources used in the conversion process. For example,
            passing ``{'metadata': {'path': run_path}}`` sets the
            execution path to ``run_path``.
        km : KernerlManager (optional)
            Optional kernel manager. If none is provided, a kernel manager will
            be created.

        Returns
        -------
        nb : NotebookNode
            The executed notebook.
        resources : dictionary
            Additional resources used in the conversion process.
        """
        path = resources.get('metadata', {}).get('path', '') or None
        self.nb = nb
        # clear display_id map
        self._display_id_map = {}
        self.widget_state = {}
        self.widget_buffers = {}

        if km is None:
            kwargs["cwd"] = path
            self.km, self.kc = self.start_new_kernel(**kwargs)
            try:
                # Yielding unbound args for more easier understanding and downstream consumption
                yield nb, self.km, self.kc
            finally:
                self.kc.stop_channels()
                self.km.shutdown_kernel(now=self.shutdown_kernel == 'immediate')

                for attr in ['nb', 'km', 'kc']:
                    delattr(self, attr)
        else:
            self.km = km
            if not km.has_kernel:
                km.start_kernel(extra_arguments=self.extra_arguments, **kwargs)
            self.kc = km.client()

            self.kc.start_channels()
            try:
                self.kc.wait_for_ready(timeout=self.startup_timeout)
            except RuntimeError:
                self.kc.stop_channels()
                raise
            self.kc.allow_stdin = False
            try:
                yield nb, self.km, self.kc
            finally:
                for attr in ['nb', 'km', 'kc']:
                    delattr(self, attr)

    def preprocess(self, nb, resources=None, km=None):
        """
        Preprocess notebook executing each code cell.

        The input argument `nb` is modified in-place.

        Parameters
        ----------
        nb : NotebookNode
            Notebook being executed.
        resources : dictionary (optional)
            Additional resources used in the conversion process. For example,
            passing ``{'metadata': {'path': run_path}}`` sets the
            execution path to ``run_path``.
        km: KernelManager (optional)
            Optional kernel manager. If none is provided, a kernel manager will
            be created.

        Returns
        -------
        nb : NotebookNode
            The executed notebook.
        resources : dictionary
            Additional resources used in the conversion process.
        """

        if not resources:
            resources = {}

        with self.setup_preprocessor(nb, resources, km=km):
            self.log.info("Executing notebook with kernel: %s" % self.kernel_name)
            nb, resources = super(ExecutePreprocessor, self).preprocess(nb, resources)
            info_msg = self._wait_for_reply(self.kc.kernel_info())
            nb.metadata['language_info'] = info_msg['content']['language_info']
            self.set_widgets_metadata()

        return nb, resources

    def set_widgets_metadata(self):
        if self.widget_state:
            self.nb.metadata.widgets = {
                'application/vnd.jupyter.widget-state+json': {
                    'state': {
                        model_id: _serialize_widget_state(state)
                        for model_id, state in self.widget_state.items() if '_model_name' in state
                    },
                    'version_major': 2,
                    'version_minor': 0,
                }
            }
            for key, widget in self.nb.metadata.widgets['application/vnd.jupyter.widget-state+json']['state'].items():
                buffers = self.widget_buffers.get(key)
                if buffers:
                    widget['buffers'] = buffers

    def preprocess_cell(self, cell, resources, cell_index, store_history=True):
        """
        Executes a single code cell. See base.py for details.

        To execute all cells see :meth:`preprocess`.
        """
        if cell.cell_type != 'code' or not cell.source.strip():
            return cell, resources

        reply, outputs = self.run_cell(cell, cell_index, store_history)
        # Backwards compatibility for processes that wrap run_cell
        cell.outputs = outputs

        cell_allows_errors = (self.allow_errors or "raises-exception"
                              in cell.metadata.get("tags", []))

        if self.force_raise_errors or not cell_allows_errors:
            for out in cell.outputs:
                if out.output_type == 'error':
                    raise CellExecutionError.from_cell_and_msg(cell, out)
            if (reply is not None) and reply['content']['status'] == 'error':
                raise CellExecutionError.from_cell_and_msg(cell, reply['content'])
        return cell, resources

    def _update_display_id(self, display_id, msg):
        """Update outputs with a given display_id"""
        if display_id not in self._display_id_map:
            self.log.debug("display id %r not in %s", display_id, self._display_id_map)
            return

        if msg['header']['msg_type'] == 'update_display_data':
            msg['header']['msg_type'] = 'display_data'

        try:
            out = output_from_msg(msg)
        except ValueError:
            self.log.error("unhandled iopub msg: " + msg['msg_type'])
            return

        for cell_idx, output_indices in self._display_id_map[display_id].items():
            cell = self.nb['cells'][cell_idx]
            outputs = cell['outputs']
            for output_idx in output_indices:
                outputs[output_idx]['data'] = out['data']
                outputs[output_idx]['metadata'] = out['metadata']

    def _poll_for_reply(self, msg_id, cell=None, timeout=None):
        try:
            # check with timeout if kernel is still alive
            msg = self.kc.shell_channel.get_msg(timeout=timeout)
            if msg['parent_header'].get('msg_id') == msg_id:
                return msg
        except Empty:
            # received no message, check if kernel is still alive
            self._check_alive()
            # kernel still alive, wait for a message

    def _get_timeout(self, cell):
        if self.timeout_func is not None and cell is not None:
            timeout = self.timeout_func(cell)
        else:
            timeout = self.timeout

        if not timeout or timeout < 0:
            timeout = None

        return timeout

    def _handle_timeout(self):
        self.log.error(
            "Timeout waiting for execute reply (%is)." % self.timeout)
        if self.interrupt_on_timeout:
            self.log.error("Interrupting kernel")
            self.km.interrupt_kernel()
        else:
            raise TimeoutError("Cell execution timed out")

    def _check_alive(self):
        if not self.kc.is_alive():
            self.log.error(
                "Kernel died while waiting for execute reply.")
            raise DeadKernelError("Kernel died")

    def _wait_for_reply(self, msg_id, cell=None):
        # wait for finish, with timeout
        timeout = self._get_timeout(cell)
        cummulative_time = 0
        timeout_interval = 5
        while True:
            try:
                msg = self.kc.shell_channel.get_msg(timeout=timeout_interval)
            except Empty:
                self._check_alive()
                cummulative_time += timeout_interval
                if timeout and cummulative_time > timeout:
                    self._handle_timeout()
                    break
            else:
                if msg['parent_header'].get('msg_id') == msg_id:
                    return msg

    def _timeout_with_deadline(self, timeout, deadline):
        if deadline is not None and deadline - monotonic() < timeout:
            timeout = deadline - monotonic()

        if timeout < 0:
            timeout = 0

        return timeout

    def _passed_deadline(self, deadline):
        if deadline is not None and deadline - monotonic() <= 0:
            self._handle_timeout()
            return True
        return False

    def run_cell(self, cell, cell_index=0, store_history=True):
        parent_msg_id = self.kc.execute(cell.source,
            store_history=store_history, stop_on_error=not self.allow_errors)
        self.log.debug("Executing cell:\n%s", cell.source)
        exec_timeout = self._get_timeout(cell)
        deadline = None
        if exec_timeout is not None:
            deadline = monotonic() + exec_timeout

        cell.outputs = []
        self.clear_before_next_output = False

        # This loop resolves #659. By polling iopub_channel's and shell_channel's
        # output we avoid dropping output and important signals (like idle) from
        # iopub_channel. Prior to this change, iopub_channel wasn't polled until
        # after exec_reply was obtained from shell_channel, leading to the
        # aforementioned dropped data.

        # These two variables are used to track what still needs polling:
        # more_output=true => continue to poll the iopub_channel
        more_output = True
        # polling_exec_reply=true => continue to poll the shell_channel
        polling_exec_reply = True

        while more_output or polling_exec_reply:
            if polling_exec_reply:
                if self._passed_deadline(deadline):
                    polling_exec_reply = False
                    continue

                # Avoid exceeding the execution timeout (deadline), but stop
                # after at most 1s so we can poll output from iopub_channel.
                timeout = self._timeout_with_deadline(1, deadline)
                exec_reply = self._poll_for_reply(parent_msg_id, cell, timeout)
                if exec_reply is not None:
                    polling_exec_reply = False

            if more_output:
                try:
                    timeout = self.iopub_timeout
                    if polling_exec_reply:
                        # Avoid exceeding the execution timeout (deadline) while
                        # polling for output.
                        timeout = self._timeout_with_deadline(timeout, deadline)
                    msg = self.kc.iopub_channel.get_msg(timeout=timeout)
                except Empty:
                    if polling_exec_reply:
                        # Still waiting for execution to finish so we expect that
                        # output may not always be produced yet.
                        continue

                    if self.raise_on_iopub_timeout:
                        raise TimeoutError("Timeout waiting for IOPub output")
                    else:
                        self.log.warning("Timeout waiting for IOPub output")
                        more_output = False
                        continue
            if msg['parent_header'].get('msg_id') != parent_msg_id:
                # not an output from our execution
                continue

            try:
                # Will raise CellExecutionComplete when completed
                self.process_message(msg, cell, cell_index)
            except CellExecutionComplete:
                more_output = False

        # Return cell.outputs still for backwards compatibility
        return exec_reply, cell.outputs

    def process_message(self, msg, cell, cell_index):
        """
        Processes a kernel message, updates cell state, and returns the
        resulting output object that was appended to cell.outputs.

        The input argument `cell` is modified in-place.

        Parameters
        ----------
        msg : dict
            The kernel message being processed.
        cell : nbformat.NotebookNode
            The cell which is currently being processed.
        cell_index : int
            The position of the cell within the notebook object.

        Returns
        -------
        output : dict
            The execution output payload (or None for no output).

        Raises
        ------
        CellExecutionComplete
          Once a message arrives which indicates computation completeness.

        """
        msg_type = msg['msg_type']
        self.log.debug("msg_type: %s", msg_type)
        content = msg['content']
        self.log.debug("content: %s", content)

        display_id = content.get('transient', {}).get('display_id', None)
        if display_id and msg_type in {'execute_result', 'display_data', 'update_display_data'}:
            self._update_display_id(display_id, msg)

        # set the prompt number for the input and the output
        if 'execution_count' in content:
            cell['execution_count'] = content['execution_count']

        if msg_type == 'status':
            if content['execution_state'] == 'idle':
                raise CellExecutionComplete()
        elif msg_type == 'clear_output':
            self.clear_output(cell.outputs, msg, cell_index)
        elif msg_type.startswith('comm'):
            self.handle_comm_msg(cell.outputs, msg, cell_index)
        # Check for remaining messages we don't process
        elif msg_type not in ['execute_input', 'update_display_data']:
            # Assign output as our processed "result"
            return self.output(cell.outputs, msg, display_id, cell_index)

    def output(self, outs, msg, display_id, cell_index):
        msg_type = msg['msg_type']

        try:
            out = output_from_msg(msg)
        except ValueError:
            self.log.error("unhandled iopub msg: " + msg_type)
            return

        if self.clear_before_next_output:
            self.log.debug('Executing delayed clear_output')
            outs[:] = []
            self.clear_display_id_mapping(cell_index)
            self.clear_before_next_output = False

        if display_id:
            # record output index in:
            #   _display_id_map[display_id][cell_idx]
            cell_map = self._display_id_map.setdefault(display_id, {})
            output_idx_list = cell_map.setdefault(cell_index, [])
            output_idx_list.append(len(outs))

        outs.append(out)

        return out

    def clear_output(self, outs, msg, cell_index):
        content = msg['content']
        if content.get('wait'):
            self.log.debug('Wait to clear output')
            self.clear_before_next_output = True
        else:
            self.log.debug('Immediate clear output')
            outs[:] = []
            self.clear_display_id_mapping(cell_index)

    def clear_display_id_mapping(self, cell_index):
        for display_id, cell_map in self._display_id_map.items():
            if cell_index in cell_map:
                cell_map[cell_index] = []

    def handle_comm_msg(self, outs, msg, cell_index):
        content = msg['content']
        data = content['data']
        if self.store_widget_state and 'state' in data:  # ignore custom msg'es
            self.widget_state.setdefault(content['comm_id'], {}).update(data['state'])
            if 'buffer_paths' in data and data['buffer_paths']:
                self.widget_buffers[content['comm_id']] = _get_buffer_data(msg)

def executenb(nb, cwd=None, km=None, **kwargs):
    """Execute a notebook's code, updating outputs within the notebook object.

    This is a convenient wrapper around ExecutePreprocessor. It returns the
    modified notebook object.

    Parameters
    ----------
    nb : NotebookNode
      The notebook object to be executed
    cwd : str, optional
      If supplied, the kernel will run in this directory
    km : KernelManager, optional
      If supplied, the specified kernel manager will be used for code execution.
    kwargs :
      Any other options for ExecutePreprocessor, e.g. timeout, kernel_name
    """
    resources = {}
    if cwd is not None:
        resources['metadata'] = {'path': cwd}
    ep = ExecutePreprocessor(**kwargs)
    return ep.preprocess(nb, resources, km=km)[0]


def _serialize_widget_state(state):
    """Serialize a widget state, following format in @jupyter-widgets/schema."""
    return {
        'model_name': state.get('_model_name'),
        'model_module': state.get('_model_module'),
        'model_module_version': state.get('_model_module_version'),
        'state': state,
    }


def _get_buffer_data(msg):
    encoded_buffers = []
    paths = msg['content']['data']['buffer_paths']
    buffers = msg['buffers']
    for path, buffer in zip(paths, buffers):
        encoded_buffers.append({
            'data': base64.b64encode(buffer).decode('utf-8'),
            'encoding': 'base64',
            'path': path
        })
    return encoded_buffers
