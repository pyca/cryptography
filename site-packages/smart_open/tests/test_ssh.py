# -*- coding: utf-8 -*-

import logging
import mock
import unittest

import smart_open.ssh


def mock_ssh(func):
    def wrapper(*args, **kwargs):
        smart_open.ssh._SSH.clear()
        return func(*args, **kwargs)

    return mock.patch("paramiko.client.SSHClient.get_transport")(
        mock.patch("paramiko.client.SSHClient.connect")(wrapper)
    )


class SSHOpen(unittest.TestCase):
    @mock_ssh
    def test_open(self, mock_connect, get_transp_mock):
        smart_open.open("ssh://user:pass@some-host/")
        mock_connect.assert_called_with("some-host", 22, username="user", password="pass")

    @mock_ssh
    def test_percent_encoding(self, mock_connect, get_transp_mock):
        smart_open.open("ssh://user%3a:pass%40@some-host/")
        mock_connect.assert_called_with("some-host", 22, username="user:", password="pass@")

    @mock_ssh
    def test_open_without_password(self, mock_connect, get_transp_mock):
        smart_open.open("ssh://user@some-host/")
        mock_connect.assert_called_with("some-host", 22, username="user", password=None)

    @mock_ssh
    def test_open_with_transport_params(self, mock_connect, get_transp_mock):
        smart_open.open(
            "ssh://user:pass@some-host/",
            transport_params={"connect_kwargs": {"username": "ubuntu", "password": "pwd"}},
        )
        mock_connect.assert_called_with("some-host", 22, username="ubuntu", password="pwd")

    @mock_ssh
    def test_open_with_key_filename(self, mock_connect, get_transp_mock):
        smart_open.open(
            "ssh://user@some-host/",
            transport_params={"connect_kwargs": {"key_filename": "key"}},
        )
        mock_connect.assert_called_with("some-host", 22, username="user", key_filename="key")


if __name__ == "__main__":
    logging.basicConfig(format="%(asctime)s : %(levelname)s : %(message)s", level=logging.DEBUG)
    unittest.main()
