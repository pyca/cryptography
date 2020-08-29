#!/usr/bin/env python
# encoding: utf-8

#------------------------------------------------------------------------------
# Application Name
#------------------------------------------------------------------------------
app_name = "naked"

#------------------------------------------------------------------------------
# Version Number
#------------------------------------------------------------------------------
major_version = "0"
minor_version = "1"
patch_version = "31"

#------------------------------------------------------------------------------
# Debug Flag (switch to False for production release code)
#------------------------------------------------------------------------------
debug = False

#------------------------------------------------------------------------------
# Usage String
#------------------------------------------------------------------------------
usage = """
Usage: naked <primary command> [secondary command] [option(s)] [argument(s)]
--- Use 'naked help' for detailed help ---
"""

#------------------------------------------------------------------------------
# Help String
#------------------------------------------------------------------------------
help = """
---------------------------------------------------
 Naked
 A Python command line application framework
 Copyright 2014 Christopher Simpkins
 MIT license
---------------------------------------------------

ABOUT

The Naked framework includes the "naked" executable and the Python toolshed library.  The naked executable is a command line tool for application development, testing, profiling, and deployment.  The toolshed library contains numerous useful tools for application development that can be used through standard Python module imports.  These features are detailed in the documentation (link below).

USAGE

The naked executable syntax is:

  naked <primary command> [secondary command] [option(s)] [argument(s)]

The <primary command> is mandatory and includes one of the commands in the following section.  The [bracketed] syntax structure is optional and dependent upon the primary command that you use.  Use the command 'naked <primary command> help' for details about a command.

PRIMARY COMMANDS     SECONDARY COMMANDS

   args                    help
   build                   help
   classify                help
   dist        all•help•sdist•swheel•wheel•win
   help                  - none -
   locate         main•help•settings•setup
   make                    help
   profile                 help
   pyh                     help
   test           nose•pytest•tox•unittest
   usage                 - none -
   version               - none -

HELP

To learn more about a primary command, use the following syntax:

  naked <primary command> help

DOCUMENTATION

  http://docs.naked-py.com

SOURCE REPOSITORY

  https://github.com/chrissimpkins/naked

ISSUE REPORTING

  https://github.com/chrissimpkins/naked/issues

"""

