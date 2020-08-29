# coding=utf-8
""" Conversion methods for different unit systems.
"""
__author__ = 'Ian Davis'


MILLISECOND = 0
SECOND = 1
MINUTE = 2
HOUR = 3
DAY = 4


def milliseconds(value, base=SECOND):
    """ Convert a number of milliseconds to the given base.

        :param value: The number of milliseconds to convert.
        :param base: The base to convert too.
        :raise TypeError: If the base given is unknown.
        :return: The converted unit.
    """
    second = 1000.0
    minute = second * 60.0
    hour = minute * 60.0
    day = hour * 24.0

    if base == MILLISECOND:
        return value
    elif base == SECOND:
        return value * second
    elif base == MINUTE:
        return value * minute
    elif base == HOUR:
        return value * hour
    elif base == DAY:
        return value * day
    else:
        raise TypeError('Unknown base for conversion: {0}'.format(base))


def seconds(value, base=SECOND):
    """ Convert a number of seconds to the given base.

        :param value: The number of seconds to convert.
        :param base: The base to convert too.
        :raise TypeError: If the base given is unknown.
        :return:  The converted unit.
    """
    millisecond = 1000.0
    minute = 60.0
    hour = minute * 60.0
    day = hour * 24.0

    if base == SECOND:
        return value
    elif base == MILLISECOND:
        return float(value) / millisecond
    elif base == MINUTE:
        return value * minute
    elif base == HOUR:
        return value * hour
    elif base == DAY:
        return value * day
    else:
        raise TypeError('Unknown base for conversion: {0}'.format(base))


def minutes(value, base=SECOND):
    """ Convert a number of minutes to the given base.

        :param value: The number of minutes to convert.
        :param base: The base to convert too.
        :raise TypeError: If the base given is unknown.
        :return:  The converted unit.
    """
    hour = 60.0
    day = hour * 24.0
    second = 60.0
    millisecond = second * 1000.0

    if base == MINUTE:
        return value
    elif base == MILLISECOND:
        return value / millisecond
    elif base == SECOND:
        return value / second
    elif base == HOUR:
        return value * hour
    elif base == DAY:
        return value * day
    else:
        raise TypeError('Unknown base for conversion: {0}'.format(base))


def hours(value, base=SECOND):
    """ Convert a number of hours to the given base.

        :param value: The number of hours to convert.
        :param base: The base to convert too.
        :raise TypeError: If the base given is unknown.
        :return:  The converted unit.
    """
    minute = 60.0
    second = minute * 60.0
    millisecond = second * 1000.0
    day = 24.0

    if base == HOUR:
        return value
    elif base == MILLISECOND:
        return value / millisecond
    elif base == SECOND:
        return value / second
    elif base == MINUTE:
        return value / minute
    elif base == DAY:
        return value * day
    else:
        raise TypeError('Unknown base for conversion: {0}'.format(base))


def days(value, base=SECOND):
    """ Convert a number of days to the given base.

        :param value: The number of days to convert.
        :param base: The base to convert the unit too.
        :raise TypeError: If the base given is unknown.
        :return: The converted unit.
    """
    hour = 24.0
    minute = hour * 60.0
    second = minute * 60.0
    millisecond = second * 1000.0

    if base == DAY:
        return value
    elif base == MILLISECOND:
        return value / millisecond
    elif base == SECOND:
        return value / second
    elif base == MINUTE:
        return value / minute
    elif base == HOUR:
        return value / hour
    else:
        raise TypeError('Unknown base for conversion: {0}'.format(base))
