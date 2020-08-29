from decimal import Decimal, ROUND_HALF_UP


def round_decimal(number):
    return int(Decimal(number).quantize(0, ROUND_HALF_UP))
