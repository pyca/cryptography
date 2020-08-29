#!/usr/bin/env python
# encoding: utf-8

#------------------------------------------------------------------------------
# Naked | A Python command line application framework
# Copyright 2014 Christopher Simpkins
# MIT License
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------------
# c.cmd = Primary command (<executable> <primary command>)
# c.cmd2 = Secondary command (<executable> <primary command> <secondary command>)
#
# c.option(option_string, [bool argument_required]) = test for option with optional test for positional arg to the option
# c.option_with_arg(option_string) = test for option and mandatory positional argument to option test
# c.flag(flag_string) = test for presence of a "--option=argument" style flag
#
# c.arg(arg_string) = returns the next positional argument to the arg_string argument
# c.flag_arg(flag_string) = returns the flag assignment for a "--option=argument" style flag
#------------------------------------------------------------------------------------

# Application start
def main():
    import sys
    from Naked.commandline import Command
    #from Naked.toolshed.state import StateObject
    from Naked.toolshed.system import stderr

    #------------------------------------------------------------------------------------------
    # [ Instantiate command line object ]
    #   used for all subsequent conditional logic in the CLI application
    #------------------------------------------------------------------------------------------
    c = Command(sys.argv[0], sys.argv[1:])
    #------------------------------------------------------------------------------
    # [ Instantiate state object ]
    #------------------------------------------------------------------------------
    #state = StateObject()
    #------------------------------------------------------------------------------------------
    # [ Command Suite Validation ] - early validation of appropriate command syntax
    #  Test that user entered a primary command, print usage if not
    #------------------------------------------------------------------------------------------
    if not c.command_suite_validates():
        from Naked.commands.usage import Usage
        Usage().print_usage()
        sys.exit(1)
    #------------------------------------------------------------------------------------------
    # [ PRIMARY COMMAND LOGIC ]
    #   Test for primary commands and handle them
    #------------------------------------------------------------------------------------------
    #------------------------------------------------------------------------------
    # [ args ] - identify the parsed arguments for a command string (2)= help
    #------------------------------------------------------------------------------
    if c.cmd == "args":
        if c.cmd2 == "help":
            from Naked.commands.args import help as args_help
            args_help()
        elif c.argc > 0: # there is an argument to where that is not help
            from Naked.commands.args import Args
            a = Args(c.arg_to_cmd)
            a.run()
        else:
            stderr("The args command requires an example command as an argument. Use 'naked args help' for more information.", 1)
    #------------------------------------------------------------------------------
    # [ build ] - build the C code in the Naked library (2)= help
    #------------------------------------------------------------------------------
    elif c.cmd == "build":
        if c.cmd2 == "help":
            from Naked.commands.build import help as build_help
            build_help()
        else:
            from Naked.commands.build import compile_c_code
            import os, inspect
            abs_dirpath = os.path.join(os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))), "toolshed", "c")
            compile_c_code(abs_dirpath) # function calls exit status code
    #------------------------------------------------------------------------------
    # [ classify ] - search Python application classifiers and display to user (args)-search string
    #------------------------------------------------------------------------------
    elif c.cmd == "classify":
        if c.cmd2 == "help":
            from Naked.commands.classifier import help as classifier_help
            classifier_help()
        else:
            if c.second: # if search string was given
                search_string = c.second
            else:
                search_string = "" # absence of search string detected in Classifier, defaults to the entire list instead of search
            from Naked.commands.classifier import Classifier
            c = Classifier(search_string)
            c.run()
    #------------------------------------------------------------------------------
    # [ dist ] - distribute source files to PyPI (2)=register, sdist, swheel, wheel, win, all, help
    #------------------------------------------------------------------------------
    elif c.cmd == "dist":
        if c.argc > 1:
            from Naked.commands.dist import Dist
            d = Dist()
            if c.cmd2 == "register": # python setup.py register
                d.run('register')
            elif c.cmd2 == "sdist":  # python setup.py sdist upload
                d.run('sdist')
            elif c.cmd2 == "swheel": # python setup.py sdist bdist_wheel upload
                d.run('swheel')
            elif c.cmd2 == "wheel":  # python setup.py bdist_wheel upload
                d.run('wheel')
            elif c.cmd2 == "win":    # python setup.py bdist_wininst upload
                d.run('win')
            elif c.cmd2 == "all":    # python setup.py sdist bdist_wheel bdist_wininst upload
                d.run('all')
            elif c.cmd2 == "help":   # help for command
                from Naked.commands.dist import help as dist_help
                dist_help()
            else:
                stderr("The naked dist secondary command was not recognized. Use 'naked dist help' for more information.", 1)
        else:
            stderr("Please enter a secondary command", 1)
    #------------------------------------------------------------------------------
    # [ locate ] - locate Naked project files (2)= main, settings, setup, help
    #------------------------------------------------------------------------------
    elif c.cmd == "locate":
        from Naked.commands.locate import Locator
        if c.cmd2 == "help":
            from Naked.commands.locate import help as locate_help
            locate_help()
        elif c.cmd2 == "main":
            l = Locator('main')
        elif c.cmd2 == "settings":
            l = Locator('settings')
        elif c.cmd2 == "setup":
            l = Locator('setup')
        else:
            l = Locator('') #handles error report to user
    #------------------------------------------------------------------------------
    # [ make ] - make a new Naked project (2)=help (args)=project name
    #------------------------------------------------------------------------------
    elif c.cmd == "make":
        from Naked.commands.make import MakeController
        if c.cmd2 == "help":
            from Naked.commands.make import help as make_help
            make_help()
        if c.arg1: # arg1 is not help so use it as the argument to the make command
            m = MakeController(c.arg1)
        else:
            m = MakeController(None)
        m.run()
    #------------------------------------------------------------------------------
    # [ profile ] - run the profiler.py file in the Naked project (2)=help
    #------------------------------------------------------------------------------
    elif c.cmd == "profile":
        if c.cmd2 == "help":
            from Naked.commands.profile import help as profile_help
            profile_help()
        else:
            from Naked.commands.profile import Profiler
            p = Profiler()
            p.run()

    #------------------------------------------------------------------------------
    # [ pyh ] - help for python built-in library modules, classes, methods, functions
    #------------------------------------------------------------------------------
    elif c.cmd == "pyh":
        if c.cmd2 == "help":
            from Naked.commands.pyh import pyh_help
            pyh_help()
        else:
            if c.argc > 1:
                from Naked.commands.pyh import python_help
                python_help(c.arg1)
            else:
                stderr("Please enter a query term with the pyh command. Use 'naked pyh help' for more information.", 1)

    #------------------------------------------------------------------------------
    # [ test ] - Run unit tests on the project (2)= help,nose,pytest,tox,unittest (see help for args)
    #------------------------------------------------------------------------------
    elif c.cmd == "test":
        if c.argc > 1:
            if c.cmd2 == "help":
                from Naked.commands.test import help as tox_help
                tox_help()
            elif c.cmd2 == "nose":
                from Naked.commands.test import NoseTester
                n = NoseTester()
                n.run()
            elif c.cmd2 == "pytest":
                from Naked.commands.test import PyTester
                p = PyTester()
                p.run()
            elif c.cmd2 == "tox":
                from Naked.commands.test import ToxTester
                if c.arg2: #user specified a python version to run with one of the tox version defs
                    t = ToxTester(c.arg2) #instantiate with the python version
                else:
                    t = ToxTester()
                t.run()
            elif c.cmd2 == "unittest":
                from Naked.commands.test import UnitTester
                if c.arg2:
                    t = UnitTester(c.arg2)
                    t.run()
                else:
                    stderr("Please include a unit test file path.  Use 'naked test help' for more information.", 1)
            else:
                stderr("The secondary command was not recognized. Use 'naked test help' for more information.", 1)
        else:
            stderr("Please include a secondary command with the 'naked test' command.  Use 'naked dist help' for more information.", 1)

    #------------------------------------------------------------------------------------------
    # [ NAKED FRAMEWORK COMMANDS ]
    # Naked framework provides default help, usage, and version commands for all applications
    #   --> settings for user messages are assigned in the lib/PROJECT/settings.py file
    #------------------------------------------------------------------------------------------
    elif c.help():  # User requested naked help (help.py module in commands directory)
        from Naked.commands.help import Help
        Help().print_help()
    elif c.usage():  # user requested naked usage info (usage.py module in commands directory)
        from Naked.commands.usage import Usage
        Usage().print_usage()
    elif c.version(): # user requested naked version (version.py module in commands directory)
        from Naked.commands.version import Version
        Version().print_version()
    #------------------------------------------------------------------------------------------
    # [ DEFAULT MESSAGE FOR MATCH FAILURE ]
    # Message to provide to the user when all above conditional logic fails to meet a true condition
    #------------------------------------------------------------------------------------------
    else:
        print("Could not complete the command that you entered.  Please try again.")
        sys.exit(1) #exit

if __name__ == '__main__':
    main()
