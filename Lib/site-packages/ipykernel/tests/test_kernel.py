# coding: utf-8
"""test the IPython Kernel"""

# Copyright (c) IPython Development Team.
# Distributed under the terms of the Modified BSD License.

import ast
import io
import os.path
import sys
import time

import nose.tools as nt
from flaky import flaky
import pytest
from packaging import version

from IPython.testing import decorators as dec, tools as tt
import IPython
from ipython_genutils import py3compat
from IPython.paths import locate_profile
from ipython_genutils.tempdir import TemporaryDirectory

from .utils import (
    new_kernel, kernel, TIMEOUT, assemble_output, execute,
    flush_channels, wait_for_idle,
)


def _check_master(kc, expected=True, stream="stdout"):
    execute(kc=kc, code="import sys")
    flush_channels(kc)
    msg_id, content = execute(kc=kc, code="print (sys.%s._is_master_process())" % stream)
    stdout, stderr = assemble_output(kc.iopub_channel)
    assert stdout.strip() == repr(expected)


def _check_status(content):
    """If status=error, show the traceback"""
    if content['status'] == 'error':
        assert False, ''.join(['\n'] + content['traceback'])


# printing tests

def test_simple_print():
    """simple print statement in kernel"""
    with kernel() as kc:
        iopub = kc.iopub_channel
        msg_id, content = execute(kc=kc, code="print ('hi')")
        stdout, stderr = assemble_output(iopub)
        assert stdout == 'hi\n'
        assert stderr == ''
        _check_master(kc, expected=True)


def test_sys_path():
    """test that sys.path doesn't get messed up by default"""
    with kernel() as kc:
        msg_id, content = execute(kc=kc, code="import sys; print(repr(sys.path))")
        stdout, stderr = assemble_output(kc.iopub_channel)
    # for error-output on failure
    sys.stderr.write(stderr)

    sys_path = ast.literal_eval(stdout.strip())
    assert '' in sys_path


def test_sys_path_profile_dir():
    """test that sys.path doesn't get messed up when `--profile-dir` is specified"""

    with new_kernel(['--profile-dir', locate_profile('default')]) as kc:
        msg_id, content = execute(kc=kc, code="import sys; print(repr(sys.path))")
        stdout, stderr = assemble_output(kc.iopub_channel)
    # for error-output on failure
    sys.stderr.write(stderr)

    sys_path = ast.literal_eval(stdout.strip())
    assert '' in sys_path


@flaky(max_runs=3)
@dec.skipif(sys.platform == 'win32', "subprocess prints fail on Windows")
def test_subprocess_print():
    """printing from forked mp.Process"""
    with new_kernel() as kc:
        iopub = kc.iopub_channel

        _check_master(kc, expected=True)
        flush_channels(kc)
        np = 5
        code = '\n'.join([
            "from __future__ import print_function",
            "import time",
            "import multiprocessing as mp",
            "pool = [mp.Process(target=print, args=('hello', i,)) for i in range(%i)]" % np,
            "for p in pool: p.start()",
            "for p in pool: p.join()",
            "time.sleep(0.5),"
        ])

        msg_id, content = execute(kc=kc, code=code)
        stdout, stderr = assemble_output(iopub)
        nt.assert_equal(stdout.count("hello"), np, stdout)
        for n in range(np):
            nt.assert_equal(stdout.count(str(n)), 1, stdout)
        assert stderr == ''
        _check_master(kc, expected=True)
        _check_master(kc, expected=True, stream="stderr")


@flaky(max_runs=3)
def test_subprocess_noprint():
    """mp.Process without print doesn't trigger iostream mp_mode"""
    with kernel() as kc:
        iopub = kc.iopub_channel

        np = 5
        code = '\n'.join([
            "import multiprocessing as mp",
            "pool = [mp.Process(target=range, args=(i,)) for i in range(%i)]" % np,
            "for p in pool: p.start()",
            "for p in pool: p.join()"
        ])

        msg_id, content = execute(kc=kc, code=code)
        stdout, stderr = assemble_output(iopub)
        assert stdout == ''
        assert stderr == ''

        _check_master(kc, expected=True)
        _check_master(kc, expected=True, stream="stderr")


@flaky(max_runs=3)
@dec.skipif(sys.platform == 'win32', "subprocess prints fail on Windows")
def test_subprocess_error():
    """error in mp.Process doesn't crash"""
    with new_kernel() as kc:
        iopub = kc.iopub_channel

        code = '\n'.join([
            "import multiprocessing as mp",
            "p = mp.Process(target=int, args=('hi',))",
            "p.start()",
            "p.join()",
        ])

        msg_id, content = execute(kc=kc, code=code)
        stdout, stderr = assemble_output(iopub)
        assert stdout == ''
        assert "ValueError" in stderr

        _check_master(kc, expected=True)
        _check_master(kc, expected=True, stream="stderr")

# raw_input tests

def test_raw_input():
    """test [raw_]input"""
    with kernel() as kc:
        iopub = kc.iopub_channel

        input_f = "input" if py3compat.PY3 else "raw_input"
        theprompt = "prompt> "
        code = 'print({input_f}("{theprompt}"))'.format(**locals())
        msg_id = kc.execute(code, allow_stdin=True)
        msg = kc.get_stdin_msg(block=True, timeout=TIMEOUT)
        assert msg['header']['msg_type'] == u'input_request'
        content = msg['content']
        assert content['prompt'] == theprompt
        text = "some text"
        kc.input(text)
        reply = kc.get_shell_msg(block=True, timeout=TIMEOUT)
        assert reply['content']['status'] == 'ok'
        stdout, stderr = assemble_output(iopub)
        assert stdout == text + "\n"


@dec.skipif(py3compat.PY3)
def test_eval_input():
    """test input() on Python 2"""
    with kernel() as kc:
        iopub = kc.iopub_channel

        input_f = "input" if py3compat.PY3 else "raw_input"
        theprompt = "prompt> "
        code = 'print(input("{theprompt}"))'.format(**locals())
        msg_id = kc.execute(code, allow_stdin=True)
        msg = kc.get_stdin_msg(block=True, timeout=TIMEOUT)
        assert msg['header']['msg_type'] == u'input_request'
        content = msg['content']
        assert content['prompt'] == theprompt
        kc.input("1+1")
        reply = kc.get_shell_msg(block=True, timeout=TIMEOUT)
        assert reply['content']['status'] == 'ok'
        stdout, stderr = assemble_output(iopub)
        assert stdout == "2\n"


def test_save_history():
    # Saving history from the kernel with %hist -f was failing because of
    # unicode problems on Python 2.
    with kernel() as kc, TemporaryDirectory() as td:
        file = os.path.join(td, 'hist.out')
        execute(u'a=1', kc=kc)
        wait_for_idle(kc)
        execute(u'b=u"abcþ"', kc=kc)
        wait_for_idle(kc)
        _, reply = execute("%hist -f " + file, kc=kc)
        assert reply['status'] == 'ok'
        with io.open(file, encoding='utf-8') as f:
            content = f.read()
        assert u'a=1' in content
        assert u'b=u"abcþ"' in content


@dec.skip_without('faulthandler')
def test_smoke_faulthandler():
    with kernel() as kc:
        # Note: faulthandler.register is not available on windows.
        code = u'\n'.join([
            'import sys',
            'import faulthandler',
            'import signal',
            'faulthandler.enable()',
            'if not sys.platform.startswith("win32"):',
            '    faulthandler.register(signal.SIGTERM)'])
        _, reply = execute(code, kc=kc)
        nt.assert_equal(reply['status'], 'ok', reply.get('traceback', ''))


def test_help_output():
    """ipython kernel --help-all works"""
    tt.help_all_output_test('kernel')


def test_is_complete():
    with kernel() as kc:
        # There are more test cases for this in core - here we just check
        # that the kernel exposes the interface correctly.
        kc.is_complete('2+2')
        reply = kc.get_shell_msg(block=True, timeout=TIMEOUT)
        assert reply['content']['status'] == 'complete'

        # SyntaxError
        kc.is_complete('raise = 2')
        reply = kc.get_shell_msg(block=True, timeout=TIMEOUT)
        assert reply['content']['status'] == 'invalid'

        kc.is_complete('a = [1,\n2,')
        reply = kc.get_shell_msg(block=True, timeout=TIMEOUT)
        assert reply['content']['status'] == 'incomplete'
        assert reply['content']['indent'] == ''

        # Cell magic ends on two blank lines for console UIs
        kc.is_complete('%%timeit\na\n\n')
        reply = kc.get_shell_msg(block=True, timeout=TIMEOUT)
        assert reply['content']['status'] == 'complete'


@dec.skipif(sys.platform != 'win32', "only run on Windows")
def test_complete():
    with kernel() as kc:
        execute(u'a = 1', kc=kc)
        wait_for_idle(kc)
        cell = 'import IPython\nb = a.'
        kc.complete(cell)
        reply = kc.get_shell_msg(block=True, timeout=TIMEOUT)

    c = reply['content']
    assert c['status'] == 'ok'
    start = cell.find('a.')
    end = start + 2
    assert c['cursor_end'] == cell.find('a.') + 2
    assert c['cursor_start'] <= end

    # there are many right answers for cursor_start,
    # so verify application of the completion
    # rather than the value of cursor_start

    matches = c['matches']
    assert matches
    for m in matches:
        completed = cell[:c['cursor_start']] + m
        assert completed.startswith(cell)


@dec.skip_without('matplotlib')
def test_matplotlib_inline_on_import():
    with kernel() as kc:
        cell = '\n'.join([
            'import matplotlib, matplotlib.pyplot as plt',
            'backend = matplotlib.get_backend()'
        ])
        _, reply = execute(cell,
            user_expressions={'backend': 'backend'},
            kc=kc)
        _check_status(reply)
        backend_bundle = reply['user_expressions']['backend']
        _check_status(backend_bundle)
        assert 'backend_inline' in backend_bundle['data']['text/plain']


def test_message_order():
    N = 100  # number of messages to test
    with kernel() as kc:
        _, reply = execute("a = 1", kc=kc)
        _check_status(reply)
        offset = reply['execution_count'] + 1
        cell = "a += 1\na"
        msg_ids = []
        # submit N executions as fast as we can
        for i in range(N):
            msg_ids.append(kc.execute(cell))
        # check message-handling order
        for i, msg_id in enumerate(msg_ids, offset):
            reply = kc.get_shell_msg(timeout=TIMEOUT)
            _check_status(reply['content'])
            assert reply['content']['execution_count'] == i
            assert reply['parent_header']['msg_id'] == msg_id


@dec.skipif(sys.platform.startswith('linux'))
def test_unc_paths():
    with kernel() as kc, TemporaryDirectory() as td:
        drive_file_path = os.path.join(td, 'unc.txt')
        with open(drive_file_path, 'w+') as f:
            f.write('# UNC test')
        unc_root = '\\\\localhost\\C$'
        file_path = os.path.splitdrive(os.path.dirname(drive_file_path))[1]
        unc_file_path = os.path.join(unc_root, file_path[1:])

        iopub = kc.iopub_channel

        kc.execute("cd {0:s}".format(unc_file_path))
        reply = kc.get_shell_msg(block=True, timeout=TIMEOUT)
        assert reply['content']['status'] == 'ok'
        out, err = assemble_output(iopub)
        assert unc_file_path in out

        flush_channels(kc)
        kc.execute(code="ls")
        reply = kc.get_shell_msg(block=True, timeout=TIMEOUT)
        assert reply['content']['status'] == 'ok'
        out, err = assemble_output(iopub)
        assert 'unc.txt' in out

        kc.execute(code="cd")
        reply = kc.get_shell_msg(block=True, timeout=TIMEOUT)
        assert reply['content']['status'] == 'ok'


def test_shutdown():
    """Kernel exits after polite shutdown_request"""
    with new_kernel() as kc:
        km = kc.parent
        execute(u'a = 1', kc=kc)
        wait_for_idle(kc)
        kc.shutdown()
        for i in range(300): # 30s timeout
            if km.is_alive():
                time.sleep(.1)
            else:
                break
        assert not km.is_alive()


def test_interrupt_during_input():
    """
    The kernel exits after being interrupted while waiting in input().
    
    input() appears to have issues other functions don't, and it needs to be
    interruptible in order for pdb to be interruptible.
    """
    with new_kernel() as kc:
        km = kc.parent
        msg_id = kc.execute("input()")
        time.sleep(1)  # Make sure it's actually waiting for input.
        km.interrupt_kernel()
        # If we failed to interrupt interrupt, this will timeout:
        reply = kc.get_shell_msg(timeout=TIMEOUT)
        from .test_message_spec import validate_message
        validate_message(reply, 'execute_reply', msg_id)


@pytest.mark.skipif(
    version.parse(IPython.__version__) < version.parse("7.14.0"),
    reason="Need new IPython"
)
def test_interrupt_during_pdb_set_trace():
    """
    The kernel exits after being interrupted while waiting in pdb.set_trace().

    Merely testing input() isn't enough, pdb has its own issues that need
    to be handled in addition.

    This test will fail with versions of IPython < 7.14.0.
    """
    with new_kernel() as kc:
        km = kc.parent
        msg_id = kc.execute("import pdb; pdb.set_trace()")
        msg_id2 = kc.execute("3 + 4")
        time.sleep(1)  # Make sure it's actually waiting for input.
        km.interrupt_kernel()
        # If we failed to interrupt interrupt, this will timeout:
        from .test_message_spec import validate_message
        reply = kc.get_shell_msg(timeout=TIMEOUT)
        validate_message(reply, 'execute_reply', msg_id)
        reply = kc.get_shell_msg(timeout=TIMEOUT)
        validate_message(reply, 'execute_reply', msg_id2)