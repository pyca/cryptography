"""Test suite for our JSON utilities."""

# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

import json
import pytest
import datetime

from datetime import timedelta
from unittest import mock
from dateutil.tz import tzlocal, tzoffset
from jupyter_client import jsonutil
from jupyter_client.session import utcnow


REFERENCE_DATETIME = datetime.datetime(
    2013, 7, 3, 16, 34, 52, 249482, tzlocal()
)


def test_extract_date_from_naive():
    ref = REFERENCE_DATETIME
    timestamp = '2013-07-03T16:34:52.249482'

    with pytest.deprecated_call(match='Interpreting naive datetime as local'):
        extracted = jsonutil.extract_dates(timestamp)

    assert isinstance(extracted, datetime.datetime)
    assert extracted.tzinfo is not None
    assert extracted.tzinfo.utcoffset(ref) == tzlocal().utcoffset(ref)
    assert extracted == ref


def test_extract_dates():
    ref = REFERENCE_DATETIME
    timestamps = [
        '2013-07-03T16:34:52.249482Z',
        '2013-07-03T16:34:52.249482-0800',
        '2013-07-03T16:34:52.249482+0800',
        '2013-07-03T16:34:52.249482-08:00',
        '2013-07-03T16:34:52.249482+08:00',
    ]
    extracted = jsonutil.extract_dates(timestamps)
    for dt in extracted:
        assert isinstance(dt, datetime.datetime)
        assert dt.tzinfo is not None

    assert extracted[0].tzinfo.utcoffset(ref) == timedelta(0)
    assert extracted[1].tzinfo.utcoffset(ref) == timedelta(hours=-8)
    assert extracted[2].tzinfo.utcoffset(ref) == timedelta(hours=8)
    assert extracted[3].tzinfo.utcoffset(ref) == timedelta(hours=-8)
    assert extracted[4].tzinfo.utcoffset(ref) == timedelta(hours=8)


def test_parse_ms_precision():
    base = '2013-07-03T16:34:52'
    digits = '1234567890'

    parsed = jsonutil.parse_date(base+'Z')
    assert isinstance(parsed, datetime.datetime)
    for i in range(len(digits)):
        ts = base + '.' + digits[:i]
        parsed = jsonutil.parse_date(ts+'Z')
        if i >= 1 and i <= 6:
            assert isinstance(parsed, datetime.datetime)
        else:
            assert isinstance(parsed, str)


def test_date_default():
    naive = datetime.datetime.now()
    local = tzoffset('Local', -8 * 3600)
    other = tzoffset('Other', 2 * 3600)
    data = dict(naive=naive, utc=utcnow(), withtz=naive.replace(tzinfo=other))
    with mock.patch.object(jsonutil, 'tzlocal', lambda : local):
        with pytest.deprecated_call(match='Please add timezone info'):
            jsondata = json.dumps(data, default=jsonutil.date_default)
    assert "Z" in jsondata
    assert jsondata.count("Z") == 1
    extracted = jsonutil.extract_dates(json.loads(jsondata))
    for dt in extracted.values():
        assert isinstance(dt, datetime.datetime)
        assert dt.tzinfo != None

