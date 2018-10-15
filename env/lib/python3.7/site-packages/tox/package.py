import json
import os
import sys
import textwrap
from collections import namedtuple
from itertools import chain

import pkg_resources
import py
import six
from filelock import FileLock, Timeout

import tox
from tox.config import DepConfig, get_py_project_toml

BuildInfo = namedtuple("BuildInfo", ["requires", "backend_module", "backend_object"])


@tox.hookimpl
def tox_package(session, venv):
    """Build an sdist at first call return that for all calls"""
    if not hasattr(session, "package"):
        session.package, session.dist = get_package(session)
    return session.package


def get_package(session):
    """"Perform the package operation"""
    config, report = session.config, session.report
    if config.skipsdist:
        report.info("skipping sdist step")
        return None
    lock_file = str(
        session.config.toxworkdir.join("{}.lock".format(session.config.isolated_build_env))
    )
    lock = FileLock(lock_file)
    try:
        try:
            lock.acquire(0.0001)
        except Timeout:
            report.verbosity0("lock file {} present, will block until released".format(lock_file))
            lock.acquire()
        package = acquire_package(config, report, session)
        session_package = create_session_view(package, config.temp_dir, report)
        return session_package, package
    finally:
        lock.release(force=True)


def create_session_view(package, temp_dir, report):
    """once we build a package we cannot return that directly, as a subsequent call
    might delete that package (in order to do its own build); therefore we need to
    return a view of the file that it's not prone to deletion and can be removed when the
    session ends
    """
    if not package:
        return package
    package_dir = temp_dir.join("package")
    package_dir.ensure(dir=True)

    # we'll number the active instances, and use the max value as session folder for a new build
    # note we cannot change package names as PEP-491 (wheel binary format)
    # is strict about file name structure
    exists = [i.basename for i in package_dir.listdir()]
    file_id = max(chain((0,), (int(i) for i in exists if six.text_type(i).isnumeric())))

    session_dir = package_dir.join(str(file_id + 1))
    session_dir.ensure(dir=True)
    session_package = session_dir.join(package.basename)

    # if we can do hard links do that, otherwise just copy
    links = False
    if hasattr(os, "link"):
        try:
            os.link(str(package), str(session_package))
            links = True
        except (OSError, NotImplementedError):
            pass
    if not links:
        package.copy(session_package)
    operation = "links" if links else "copied"
    common = session_package.common(package)
    report.verbosity1(
        "package {} {} to {} ({})".format(
            common.bestrelpath(session_package), operation, common.bestrelpath(package), common
        )
    )
    return session_package


def acquire_package(config, report, session):
    """acquire a source distribution (either by loading a local file or triggering a build)"""
    if not config.option.sdistonly and (config.sdistsrc or config.option.installpkg):
        path = get_local_package(config, report, session)
    else:
        try:
            path = build_package(config, report, session)
        except tox.exception.InvocationError as exception:
            report.error("FAIL could not package project - v = {!r}".format(exception))
            return None
        sdist_file = config.distshare.join(path.basename)
        if sdist_file != path:
            report.info("copying new sdistfile to {!r}".format(str(sdist_file)))
            try:
                sdist_file.dirpath().ensure(dir=1)
            except py.error.Error:
                report.warning("could not copy distfile to {}".format(sdist_file.dirpath()))
            else:
                path.copy(sdist_file)
    return path


def get_local_package(config, report, session):
    path = config.option.installpkg
    if not path:
        path = config.sdistsrc
    py_path = py.path.local(session._resolve_package(path))
    report.info("using package {!r}, skipping 'sdist' activity ".format(str(py_path)))
    return py_path


def build_package(config, report, session):
    if not config.isolated_build:
        return make_sdist_legacy(report, config, session)
    else:
        return build_isolated(config, report, session)


def make_sdist_legacy(report, config, session):
    setup = config.setupdir.join("setup.py")
    if not setup.check():
        report.error(
            "No setup.py file found. The expected location is:\n"
            "  {}\n"
            "You can\n"
            "  1. Create one:\n"
            "     https://packaging.python.org/tutorials/distributing-packages/#setup-py\n"
            "  2. Configure tox to avoid running sdist:\n"
            "     https://tox.readthedocs.io/en/latest/example/general.html"
            "#avoiding-expensive-sdist".format(setup)
        )
        raise SystemExit(1)
    with session.newaction(None, "packaging") as action:
        action.setactivity("sdist-make", setup)
        session.make_emptydir(config.distdir)
        build_log = action.popen(
            [sys.executable, setup, "sdist", "--formats=zip", "--dist-dir", config.distdir],
            cwd=config.setupdir,
            returnout=True,
        )
        report.verbosity2(build_log)
        try:
            return config.distdir.listdir()[0]
        except py.error.ENOENT:
            # check if empty or comment only
            data = []
            with open(str(setup)) as fp:
                for line in fp:
                    if line and line[0] == "#":
                        continue
                    data.append(line)
            if not "".join(data).strip():
                report.error("setup.py is empty")
                raise SystemExit(1)
            report.error(
                "No dist directory found. Please check setup.py, e.g with:\n"
                "     python setup.py sdist"
            )
            raise SystemExit(1)


def build_isolated(config, report, session):
    build_info = get_build_info(config.setupdir, report)
    package_venv = session.getvenv(config.isolated_build_env)
    package_venv.envconfig.deps_matches_subset = True

    # we allow user specified dependencies so the users can write extensions to
    # install additional type of dependencies (e.g. binary)
    user_specified_deps = package_venv.envconfig.deps
    package_venv.envconfig.deps = [DepConfig(r, None) for r in build_info.requires]
    package_venv.envconfig.deps.extend(user_specified_deps)

    if session.setupenv(package_venv):
        session.finishvenv(package_venv)

    build_requires = get_build_requires(build_info, package_venv, session)
    # we need to filter out requirements already specified in pyproject.toml or user deps
    base_build_deps = {pkg_resources.Requirement(r.name).key for r in package_venv.envconfig.deps}
    build_requires_dep = [
        DepConfig(r, None)
        for r in build_requires
        if pkg_resources.Requirement(r).key not in base_build_deps
    ]
    if build_requires_dep:
        with session.newaction(
            package_venv, "build_requires", package_venv.envconfig.envdir
        ) as action:
            package_venv.run_install_command(packages=build_requires_dep, action=action)
        session.finishvenv(package_venv)
    return perform_isolated_build(build_info, package_venv, session, config, report)


def get_build_info(folder, report):
    toml_file = folder.join("pyproject.toml")

    # as per https://www.python.org/dev/peps/pep-0517/

    def abort(message):
        report.error("{} inside {}".format(message, toml_file))
        raise SystemExit(1)

    if not toml_file.exists():
        report.error("missing {}".format(toml_file))
        raise SystemExit(1)

    config_data = get_py_project_toml(toml_file)

    if "build-system" not in config_data:
        abort("build-system section missing")

    build_system = config_data["build-system"]

    if "requires" not in build_system:
        abort("missing requires key at build-system section")
    if "build-backend" not in build_system:
        abort("missing build-backend key at build-system section")

    requires = build_system["requires"]
    if not isinstance(requires, list) or not all(isinstance(i, six.text_type) for i in requires):
        abort("requires key at build-system section must be a list of string")

    backend = build_system["build-backend"]
    if not isinstance(backend, six.text_type):
        abort("build-backend key at build-system section must be a string")

    args = backend.split(":")
    module = args[0]
    obj = "" if len(args) == 1 else ".{}".format(args[1])

    return BuildInfo(requires, module, "{}{}".format(module, obj))


def perform_isolated_build(build_info, package_venv, session, config, report):
    with session.newaction(
        package_venv, "perform-isolated-build", package_venv.envconfig.envdir
    ) as action:
        script = textwrap.dedent(
            """
            import sys
            import {}
            basename = {}.build_{}({!r}, {{ "--global-option": ["--formats=gztar"]}})
            print(basename)""".format(
                build_info.backend_module, build_info.backend_object, "sdist", str(config.distdir)
            )
        )

        # need to start with an empty (but existing) source distribution folder
        if config.distdir.exists():
            config.distdir.remove(rec=1, ignore_errors=True)
        config.distdir.ensure_dir()

        result = package_venv._pcall(
            [package_venv.envconfig.envpython, "-c", script],
            returnout=True,
            action=action,
            cwd=session.config.setupdir,
        )
        report.verbosity2(result)
        return config.distdir.join(result.split("\n")[-2])


def get_build_requires(build_info, package_venv, session):
    with session.newaction(
        package_venv, "get-build-requires", package_venv.envconfig.envdir
    ) as action:
        script = textwrap.dedent(
            """
                import {}
                import json

                backend = {}
                for_build_requires = backend.get_requires_for_build_{}(None)
                print(json.dumps(for_build_requires))
                        """.format(
                build_info.backend_module, build_info.backend_object, "sdist"
            )
        ).strip()
        result = package_venv._pcall(
            [package_venv.envconfig.envpython, "-c", script],
            returnout=True,
            action=action,
            cwd=session.config.setupdir,
        )
        return json.loads(result.split("\n")[-2])
