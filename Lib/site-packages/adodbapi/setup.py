"""adodbapi -- a pure Python PEP 249 DB-API package using Microsoft ADO

Adodbapi can be run on CPython version 2.7,
or IronPython version 2.6 and later,
or Python 3.5 and later (after filtering through 2to3.py)
"""
CLASSIFIERS = """\
Development Status :: 5 - Production/Stable
Intended Audience :: Developers
License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)
Operating System :: Microsoft :: Windows
Operating System :: POSIX :: Linux
Programming Language :: Python
Programming Language :: Python :: 3
Programming Language :: SQL
Topic :: Software Development
Topic :: Software Development :: Libraries :: Python Modules
Topic :: Database
"""

NAME                = 'adodbapi'
MAINTAINER          = "Vernon Cole"
MAINTAINER_EMAIL    = "vernondcole@gmail.com"
DESCRIPTION         = """A pure Python package implementing PEP 249 DB-API using Microsoft ADO."""
URL                 = "http://sourceforge.net/projects/adodbapi"
LICENSE             = 'LGPL'
CLASSIFIERS         = filter(None, CLASSIFIERS.split('\n'))
AUTHOR              = "Henrik Ekelund, Vernon Cole, et.al."
AUTHOR_EMAIL        = "vernondcole@gmail.com"
PLATFORMS           = ["Windows","Linux"]

VERSION = None # in case searching for version fails
a = open('adodbapi.py') # find the version string in the source code
for line in a:
    if '__version__' in line:
        VERSION = line.split("'")[1]
        print(('adodbapi version="%s"' % VERSION))
        break
a.close()

##DOWNLOAD_URL = "http://sourceforge.net/projects/adodbapi/files/adodbapi/" + VERSION.rsplit('.', 1)[0] + '/adodbapi-' + VERSION + '.zip'

import sys
def setup_package():

    from distutils.core import setup

    if sys.version_info >= (3, 0):

        try:
            from distutils.command.build_py import build_py_2to3 as build_py
##        # exclude fixers that break already compatible code
##        from lib2to3.refactor import get_fixers_from_package
##        fixers = get_fixers_from_package('lib2to3.fixes')
##        for skip_fixer in ['import']:
##            fixers.remove('lib2to3.fixes.fix_' + skip_fixer)
##        build_py.fixer_names = fixers
        except ImportError:
            raise ImportError("build_py_2to3 not found in distutils - it is required for Python 3.x")
    else:
        from distutils.command.build_py import build_py

    setup(
        cmdclass = {'build_py': build_py},
        name=NAME,
        maintainer=MAINTAINER,
        maintainer_email=MAINTAINER_EMAIL,
        description=DESCRIPTION,
        url=URL,
        keywords='database ado odbc dbapi db-api Microsoft SQL',
##        download_url=DOWNLOAD_URL,
        long_description=open('README.txt').read(),
        license=LICENSE,
        classifiers=CLASSIFIERS,
        author=AUTHOR,
        author_email=AUTHOR_EMAIL,
        platforms=PLATFORMS,
        version=VERSION,
        package_dir = {'adodbapi':''},
        packages=['adodbapi'] )
    return

if __name__ == '__main__':
    setup_package()
