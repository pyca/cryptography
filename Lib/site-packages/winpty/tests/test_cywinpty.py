# -*- coding: utf-8 -*-
"""Cywinpty tests."""

# yapf: disable

# Third party imports
from winpty.cywinpty import Agent
from winpty.winpty_wrapper import PY2
from winpty.ptyprocess import which
import pytest


# yapf: disable

CMD = which('cmd')
if PY2:
    CMD = unicode(CMD)  # noqa


@pytest.fixture(scope='module')
def agent_fixture():
    def _agent_factory(cols, rows):
        agent = Agent(cols, rows)
        return agent
    return _agent_factory


def test_agent_spawn(agent_fixture):
    agent = agent_fixture(80, 25)
    succ = agent.spawn(CMD)
    assert succ
    del agent


def test_agent_spawn_fail(agent_fixture):
    agent = agent_fixture(80, 25)
    try:
        agent.spawn(CMD)
    except RuntimeError:
        pass


def test_agent_spawn_size_fail(agent_fixture):
    try:
        agent_fixture(80, -25)
    except RuntimeError:
        pass


def test_agent_resize(agent_fixture):
    agent = agent_fixture(80, 25)
    agent.set_size(80, 70)
    del agent


def test_agent_resize_fail(agent_fixture):
    agent = agent_fixture(80, 25)
    try:
        agent.set_size(-80, 70)
    except RuntimeError:
        pass
