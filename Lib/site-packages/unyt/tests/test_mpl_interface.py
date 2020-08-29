"""Test Matplotlib ConversionInterface"""
import numpy as np
import pytest
from unyt._on_demand_imports import _matplotlib, NotAModule
from unyt import m, s, K, unyt_array, unyt_quantity
from unyt.exceptions import UnitConversionError

try:
    from unyt import matplotlib_support
    from unyt.mpl_interface import unyt_arrayConverter
except ImportError:
    pass

check_matplotlib = pytest.mark.skipif(
    isinstance(_matplotlib.pyplot, NotAModule), reason="matplotlib not installed"
)


@pytest.fixture
def ax():
    _matplotlib.use("agg")
    matplotlib_support.enable()
    matplotlib_support.label_style = "()"
    fig, ax = _matplotlib.pyplot.subplots()
    yield ax
    _matplotlib.pyplot.close()
    matplotlib_support.disable()


@check_matplotlib
def test_label(ax):
    x = [0, 1, 2] * s
    y = [3, 4, 5] * K
    matplotlib_support.label_style = "()"
    ax.plot(x, y)
    expected_xlabel = "$\\left(\\rm{s}\\right)$"
    assert ax.xaxis.get_label().get_text() == expected_xlabel
    expected_ylabel = "$\\left(\\rm{K}\\right)$"
    assert ax.yaxis.get_label().get_text() == expected_ylabel
    _matplotlib.pyplot.close()


@check_matplotlib
def test_convert_unit(ax):
    x = [0, 1, 2] * s
    y = [1000, 2000, 3000] * K
    ax.plot(x, y, yunits="Celsius")
    expected = y.to("Celsius")
    line = ax.lines[0]
    original_y_array = line.get_data()[1]
    converted_y_array = line.convert_yunits(original_y_array)
    results = converted_y_array == expected
    assert results.all()


@check_matplotlib
def test_convert_equivalency(ax):
    x = [0, 1, 2] * s
    y = [1000, 2000, 3000] * K
    ax.clear()
    ax.plot(x, y, yunits=("J", "thermal"))
    expected = y.to("J", "thermal")
    line = ax.lines[0]
    original_y_array = line.get_data()[1]
    converted_y_array = line.convert_yunits(original_y_array)
    results = converted_y_array == expected
    assert results.all()


@check_matplotlib
def test_dimensionless(ax):
    x = [0, 1, 2] * s
    y = [3, 4, 5] * K / K
    ax.plot(x, y)
    expected_ylabel = ""
    assert ax.yaxis.get_label().get_text() == expected_ylabel


@check_matplotlib
def test_conversionerror(ax):
    x = [0, 1, 2] * s
    y = [3, 4, 5] * K
    ax.plot(x, y)
    ax.xaxis.callbacks.exception_handler = None
    # Newer matplotlib versions catch our exception and raise a custom
    # ConversionError exception
    try:
        error_type = _matplotlib.units.ConversionError
    except AttributeError:
        error_type = UnitConversionError
    with pytest.raises(error_type):
        ax.xaxis.set_units("V")


@check_matplotlib
def test_ndarray_label(ax):
    x = [0, 1, 2] * s
    y = np.arange(3, 6)
    matplotlib_support.label_style = "()"
    ax.plot(x, y)
    expected_xlabel = "$\\left(\\rm{s}\\right)$"
    assert ax.xaxis.get_label().get_text() == expected_xlabel
    expected_ylabel = ""
    assert ax.yaxis.get_label().get_text() == expected_ylabel


@check_matplotlib
def test_list_label(ax):
    x = [0, 1, 2] * s
    y = [3, 4, 5]
    matplotlib_support.label_style = "()"
    ax.plot(x, y)
    expected_xlabel = "$\\left(\\rm{s}\\right)$"
    assert ax.xaxis.get_label().get_text() == expected_xlabel
    expected_ylabel = ""
    assert ax.yaxis.get_label().get_text() == expected_ylabel


@check_matplotlib
def test_errorbar(ax):
    x = unyt_array([8, 9, 10], "cm")
    y = unyt_array([8, 9, 10], "kg")
    y_scatter = [unyt_array([0.1, 0.2, 0.3], "kg"), unyt_array([0.1, 0.2, 0.3], "kg")]
    x_lims = (unyt_quantity(5, "cm"), unyt_quantity(12, "cm"))
    y_lims = (unyt_quantity(5, "kg"), unyt_quantity(12, "kg"))
    ax.errorbar(x, y, yerr=y_scatter)
    x_lims = (unyt_quantity(5, "cm"), unyt_quantity(12, "cm"))
    y_lims = (unyt_quantity(5, "kg"), unyt_quantity(12, "kg"))
    ax.set_xlim(*x_lims)
    ax.set_ylim(*y_lims)


@check_matplotlib
def test_hist2d(ax):
    x = np.random.normal(size=50000) * s
    y = 3 * x + np.random.normal(size=50000) * s
    ax.hist2d(x, y, bins=(50, 50))


@check_matplotlib
def test_imshow(ax):
    data = np.reshape(np.random.normal(size=10000), (100, 100))
    ax.imshow(data, vmin=data.min(), vmax=data.max())


@check_matplotlib
def test_hist(ax):
    data = np.random.normal(size=10000) * s
    bin_edges = np.linspace(data.min(), data.max(), 50)
    ax.hist(data, bins=bin_edges)


@check_matplotlib
def test_matplotlib_support():
    with pytest.raises(KeyError):
        _matplotlib.units.registry[unyt_array]
    matplotlib_support.enable()
    assert isinstance(_matplotlib.units.registry[unyt_array], unyt_arrayConverter)
    matplotlib_support.disable()
    assert unyt_array not in _matplotlib.units.registry.keys()
    assert unyt_quantity not in _matplotlib.units.registry.keys()
    # test as a callable
    matplotlib_support()
    assert isinstance(_matplotlib.units.registry[unyt_array], unyt_arrayConverter)


@check_matplotlib
def test_labelstyle():
    x = [0, 1, 2] * s
    y = [3, 4, 5] * K
    matplotlib_support.label_style = "[]"
    assert matplotlib_support.label_style == "[]"
    matplotlib_support.enable()
    assert unyt_arrayConverter._labelstyle == "[]"
    fig, ax = _matplotlib.pyplot.subplots()
    ax.plot(x, y)
    expected_xlabel = "$\\left[\\rm{s}\\right]$"
    assert ax.xaxis.get_label().get_text() == expected_xlabel
    expected_ylabel = "$\\left[\\rm{K}\\right]$"
    assert ax.yaxis.get_label().get_text() == expected_ylabel
    matplotlib_support.label_style = "/"
    ax.clear()
    x.name = "$t$"
    ax.plot(x, y)
    expected_xlabel = "$t$ $\\;/\\;\\rm{s}$"
    assert ax.xaxis.get_label().get_text() == expected_xlabel
    expected_ylabel = "$q_{\\rmy}$$\\;/\\;\\rm{K}$"
    assert ax.yaxis.get_label().get_text() == expected_ylabel
    x = [0, 1, 2] * m / s
    ax.clear()
    ax.plot(x, y)
    expected_xlabel = "$q_{\\rmx}$$\\;/\\;\\left(\\rm{m} / \\rm{s}\\right)$"
    assert ax.xaxis.get_label().get_text() == expected_xlabel
    _matplotlib.pyplot.close()
    matplotlib_support.disable()


@check_matplotlib
def test_name(ax):
    x = unyt_array([0, 1, 2], "s", name="time")
    assert x.name == "time"
    y = unyt_array([3, 4, 5], "m", name="distance")
    ax.plot(x, y)
    expected_xlabel = "time $\\left(\\rm{s}\\right)$"
    assert ax.xaxis.get_label().get_text() == expected_xlabel
    expected_ylabel = "distance $\\left(\\rm{m}\\right)$"
    assert ax.yaxis.get_label().get_text() == expected_ylabel
    ax.clear()
    ax.plot(x, y, xunits="ms")
    expected_xlabel = "time $\\left(\\rm{ms}\\right)$"


@check_matplotlib
def test_multiple_subplots():
    x1 = unyt_array([0, 1, 2], "s", name="time")
    y1 = unyt_array([6, 7, 8], "m", name="distance")
    x2 = unyt_array([3, 4, 5], "V", name="voltage")
    y2 = unyt_array([9, 10, 11], "A", name="current")
    matplotlib_support.enable()
    fig, ax = _matplotlib.pyplot.subplots(nrows=1, ncols=2)
    ax[0].plot(x1, y1)
    ax[1].plot(x2, y2)
    expected_labels = [
        "time $\\left(\\rm{s}\\right)$",
        "distance $\\left(\\rm{m}\\right)$",
        "voltage $\\left(\\rm{V}\\right)$",
        "current $\\left(\\rm{A}\\right)$",
    ]
    generated_labels = []
    for subplot in ax:
        xlabel = subplot.xaxis.get_label().get_text()
        ylabel = subplot.yaxis.get_label().get_text()
        generated_labels.extend((xlabel, ylabel))
    assert generated_labels == expected_labels
    _matplotlib.pyplot.close()
    matplotlib_support.disable()
