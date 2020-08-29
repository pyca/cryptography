#!/usr/bin/env python
# encoding: utf-8

# VARS: app_name, developer, license
setup_py_string = ("""
import os
import re
from setuptools import setup, find_packages


def docs_read(fname):
    return open(os.path.join(os.path.dirname(__file__), 'docs', fname)).read()

def version_read():
    settings_file = open(os.path.join(os.path.dirname(__file__), 'lib', '{{app_name}}', 'settings.py')).read()
    major_regex = """ + '"""' + """major_version\s*?=\s*?["']{1}(\d+)["']{1}""" + '"""' + '\n    ' +
    'minor_regex = ' + '"""' + """minor_version\s*?=\s*?["']{1}(\d+)["']{1}""" + '"""' + '\n    ' +
    'patch_regex = ' + '"""' + """patch_version\s*?=\s*?["']{1}(\d+)["']{1}""" + '"""' + '\n    ' +
    """major_match = re.search(major_regex, settings_file)
    minor_match = re.search(minor_regex, settings_file)
    patch_match = re.search(patch_regex, settings_file)
    major_version = major_match.group(1)
    minor_version = minor_match.group(1)
    patch_version = patch_match.group(1)
    if len(major_version) == 0:
        major_version = 0
    if len(minor_version) == 0:
        minor_version = 0
    if len(patch_version) == 0:
        patch_version = 0
    return major_version + "." + minor_version + "." + patch_version


setup(
    name='{{app_name}}',
    version=version_read(),
    description='',
    long_description=(docs_read('README.rst')),
    url='',
    license='{{license}}',
    author='{{developer}}',
    author_email='',
    platforms=['any'],
    entry_points = {
        'console_scripts': [
            '{{app_name}} = {{app_name}}.app:main'
        ],
    },
    packages=find_packages("lib"),
    package_dir={'': 'lib'},
    install_requires=['Naked'],
    keywords='',
    include_package_data=True,
    classifiers=[],
)
""")
