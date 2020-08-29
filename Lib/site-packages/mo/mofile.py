"""Utilities for working with M-O task files."""

from pathlib import Path
import json

import toml
import yaml

from .project import Project


class InvalidMofileFormat(ValueError):
    pass


formats = {
    'yaml': (yaml.safe_load, yaml.YAMLError),
    'json': (json.loads, json.JSONDecodeError),
    'toml': (toml.loads, toml.TomlDecodeError),
}


def _load_autodetect(data):
    for loader, error_class in formats.values():
        try:
            return loader(data)
        except error_class:
            pass
    else:
        raise InvalidMofileFormat('Cannot detect file format.')


def load(filename, format=None):
    """Load a task file and get a ``Project`` back."""

    path = Path(filename).resolve()

    with path.open() as file:
        data = file.read()

    if format is None:
        loader, error_class = _load_autodetect, InvalidMofileFormat
    else:
        try:
            loader, error_class = formats[format]
        except KeyError:
            raise InvalidMofileFormat(f'Unknown file format: {format}')

    try:
        config = loader(data)
    except error_class as e:
        raise InvalidMofileFormat(f'Unable to load task file: {e}')

    return Project(config, path.parent)
