import pytest

from nbformat import read


def test_read_invalid_iowrapper(tmpdir):
    ipynb_filepath = tmpdir.join("empty.ipynb")
    ipynb_filepath.write("{}")

    with pytest.raises(AttributeError) as excinfo:
        with ipynb_filepath.open() as fp:
            read(fp, as_version=4)
    assert "cells" in str(excinfo.value)


def test_read_invalid_filepath(tmpdir):
    ipynb_filepath = tmpdir.join("empty.ipynb")
    ipynb_filepath.write("{}")

    with pytest.raises(AttributeError) as excinfo:
        read(str(ipynb_filepath), as_version=4)
    assert "cells" in str(excinfo.value)


def test_read_invalid_pathlikeobj(tmpdir):
    ipynb_filepath = tmpdir.join("empty.ipynb")
    ipynb_filepath.write("{}")

    with pytest.raises(AttributeError) as excinfo:
        read(ipynb_filepath, as_version=4)
    assert "cells" in str(excinfo.value)


def test_read_invalid_str(tmpdir):
    with pytest.raises(OSError) as excinfo:
        read("not_exist_path", as_version=4)
    assert "No such file or directory" in str(excinfo.value)


def test_read_invalid_type(tmpdir):
    with pytest.raises(OSError) as excinfo:
        read(123, as_version=4)
