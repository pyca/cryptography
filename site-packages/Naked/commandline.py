#!/usr/bin/env python
# encoding: utf-8

import sys
from Naked.settings import debug as DEBUG_FLAG
#####################################################################
# [ Command class ]
# Command line command string object
#   argv = list of command line arguments and options
#   argc = count of command line arguments and options
#   arg0 = first positional argument to command
#   arg1 = second positional argument to command
#   arglp = last positional argument to command
#   cmd = primary command for command suite application (=arg0)
#   cmd2 = secondary command for command suite application (=arg1)
#      snippet for py block comment = #py + TAB
#####################################################################
class Command:
    def __init__(self, app_path, argv):
        self.argobj = Argument(argv) # create an Argument obj
        self.optobj = Option(argv) # create an Option obj
        self.app = app_path   # path to application executable file
        self.argv = argv    # list of the command arguments argv[0] is first argument
        self.argc = len(argv)  # length of the argument list
        self.arg0 = self.argobj._getArg(0) # define the first positional argument
        self.arg1 = self.argobj._getArg(1) # define the second positional argument
        self.arg2 = self.argobj._getArg(2) # define the third postitional argument
        self.arg3 = self.argobj._getArg(3) # define the fourth positional argument
        self.arg4 = self.argobj._getArg(4) # define the fifth positional argument
        self.arglp = self.argobj._getArg(len(argv) - 1) # define the last positional argument
        self.first = self.arg0
        self.second = self.arg1
        self.third = self.arg2
        self.fourth = self.arg3
        self.fifth = self.arg4
        self.last = self.arglp
        self.arg_to_exec = self.arg0 # argument to the executable
        self.arg_to_cmd = self.arg1 # argument to the primary command
        self.cmd = self.arg0  # define the primary command variable as the first positional argument (user dependent & optional, may be something else)
        self.cmd2 = self.arg1 # define the secondary command variable as the second positional argument (user dependent & optional, may be something else)
        self.options = self.option_exists() # test for presence of at least one option (boolean)
        self.flags = self.flag_exists() # test for presence of at least one flag (boolean)

    #------------------------------------------------------------------------------
    # [ app_validates_args method ] (boolean)
    #   Test whether app validates on the criterion arguments (argc) > 0, i.e. there is at least one argument to the executable
    #------------------------------------------------------------------------------
    def app_validates_args(self):
        try:
            if self.argc > 0:
                return True
            else:
                return False
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Validation of application error in the app_validates() method (Naked.commandline.py).")
            raise e

    #------------------------------------------------------------------------------------------
    # [ arg method ] (string)
    # Return the NEXT positional argument to a command line object (e.g. an option that requires an argument)
    #    arg_recipient = the positional argument (at position n) to test for next positional argument
    #    returns next positional argument string at position n + 1
    #------------------------------------------------------------------------------------------
    def arg(self, arg_recipient):
        try:
            recipient_position = self.argobj._getArgPosition(arg_recipient)
            return self.argobj._getArgNext(recipient_position)
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Error parsing argument with arg() method (Naked.commandline.py).")
            raise e

    #------------------------------------------------------------------------------------------
    # [ command method ] (boolean)
    # Test that the command includes requested primary command suite command (cmd_str parameter)
    #    cmd_str = the command string to test for in command
    #    arugment_required = boolean - is an argument to this command required (default = no)?
    #    returns boolean for presence of the cmd_str
    #------------------------------------------------------------------------------------------
    def command(self, cmd_str):
        try:
            if (cmd_str == self.cmd):
                return True
            else:
                return False # if command is missing, return false
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Error parsing command with command() method (Naked.commandline.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ command_arg method ] (string)
    #  Return the argument to the primary command as a string
    #------------------------------------------------------------------------------
    def command_arg(self):
        try:
            return self.arg1
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Error parsing command argument with command_arg() method (Naked.commandline.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ command2_arg method ] (string)
    #  Return the argument to the secondary command as a string
    #------------------------------------------------------------------------------
    def command2_arg(self):
        try:
            return self.arg2
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Error parsing command argument with command_arg() method (Naked.commandline.py).")
            raise e
    #------------------------------------------------------------------------------------------
    # [ command_with_argument method ] (boolean)
    # Test that the command includes requested primary command suite command (cmd_str parameter) and argument to it
    #    cmd_str = the command string to test for in command
    #    returns boolean for presence of the cmd_str AND presence of argument to the command
    #------------------------------------------------------------------------------------------
    def command_with_argument(self, cmd_str):
        try:
            if (cmd_str == self.cmd):
                argument_to_cmd = self.argobj._getArgNext(0)
                if argument_to_cmd == "": # if the argument is missing, then return false
                    return False
                else:
                    return True
            else:
                return False # if command is missing return false
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Error parsing command and argument with command_with_argument() method (Naked.commandline.py).")
            raise e

    #------------------------------------------------------------------------------------------
    # [ command_suite_validates method ] (boolean)
    #    Test that there is a primary command in a command suite application (to be used at the top level of logic for command line application)
    #    returns boolean for presence of the primary command
    #------------------------------------------------------------------------------------------
    def command_suite_validates(self, accept_options_as_argument = True):
        try:
            if self.argc > 0:
                if self.arg0.startswith("-") and accept_options_as_argument == False:
                    return False # if no command and option present, return False
                else:
                    return True # if a primary command present, return True
            else:
                return False # if user only entered the application name, return False
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Command suite validation error with the command_suite_validation() method (Naked.commandline.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ flag method ] (boolean)
    #   Test for presence of flag in the command
    #------------------------------------------------------------------------------
    def flag(self, flag_string):
        try:
            for match_string in self.optobj: #iterate through the options and attempt to match beginning of option to the requested flag
                if match_string.startswith(flag_string):
                    return True
                else:
                    pass
            return False
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Error parsing flags with the flag() method (Naked.commandline.py).")
            raise e

    #------------------------------------------------------------------------------
    # [flag_arg method] (string)
    #   Return the argument string assigned to a flag
    #------------------------------------------------------------------------------
    def flag_arg(self, flag_string):
        try:
            for match_string in self.optobj:
                if match_string.startswith(flag_string) and '=' in match_string:
                    flag_list = match_string.split("=") #split the flag on the equal symbol = list with [option, argument]
                    return flag_list[1] #return the argument to the flag option
                else:
                    pass
            return "" # return an empty string if unable to parse the argument
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Error parsing flags with the flag_arg() method (Naked.commandline.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ flag_exists method ] (boolean)
    #  Test for the presence of a flag style option (--flag=argument) in the command
    #------------------------------------------------------------------------------
    def flag_exists(self):
        try:
            for item in self.optobj:
                if '=' in item: #test for presence of an = symbol in the option
                    return True # if present return True
                    break
            return False        # if didn't match across all options, return False
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Error parsing flags with the flag_arg() method (Naked.commandline.py).")
            raise e

    #------------------------------------------------------------------------------------------
    # [ option method ] (boolean)
    #   Test that the command includes an option (option_string parameter)
    #    option_string = the option string to test for in the command
    #    arugment_required = boolean - is an argument to this option required (default = no)?
    #    returns boolean for presence of the cmd_str
    #------------------------------------------------------------------------------------------
    def option(self, option_string, argument_required = False):
        try:
            if (option_string in self.optobj):
                argument_to_option = self.argobj._getArgNext(self.argobj._getArgPosition(option_string))
                if argument_required and ( argument_to_option == "" or argument_to_option.startswith("-") ):
                    return False
                else:
                    return True
            else:
                return False
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Error parsing option with option() method (Naked.commandline.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ option_arg method ] (string)
    #  Return the argument string to an option
    #------------------------------------------------------------------------------
    def option_arg(self, option_string):
        try:
            return self.argobj._getArgNext(self.argobj._getArgPosition(option_string))
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Error returning argument to option with option_arg() method (Naked.commandline.py).")
            raise e

    #------------------------------------------------------------------------------------------
    # [ option_with_arg method ] (boolean)
    # Test that the command includes an option (option_string parameter) and argument to that option
    #    option_string = the option string to test for in the command
    #    arugment_required = boolean - is an argument to this option required (default = yes)?
    #    returns boolean for presence of the option_string AND the argument
    #------------------------------------------------------------------------------------------
    # test that command includes an option (option_string parameter) that includes an argument (=option(option_string, True))
    def option_with_arg(self, option_string, argument_required = True):
        try:
            if (option_string in self.optobj):
                argument_to_option = self.argobj._getArgNext(self.argobj._getArgPosition(option_string))
                if argument_required and ( argument_to_option == "" or argument_to_option.startswith("-") ):
                    return False # argument is either missing or is another option, return false
                else:
                    return True
            else:
                return False # option is not present
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Error parsing option and argument with option_with_arg() method (Naked.commandline.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ option_exists method ] (boolean)
    #  Test whether there are any options in the command string
    #  returns boolean value for test "Is there at least one option?"
    #------------------------------------------------------------------------------
    def option_exists(self):
        try:
            if len(self.optobj) > 0:
                return True
            else:
                return False
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Error testing for the presence of at least one option with option_exists() method (Naked.commandline.py).")
            raise e
    #------------------------------------------------------------------------------
    #  Naked provides the following commands for all applications that use the framework:
    #  -- help
    #  -- usage
    #  -- version
    #  These methods are accessed from the app.py module, main() as method calls on the command line object
    #  Parsing logic is coded below
    #------------------------------------------------------------------------------

    #------------------------------------------------------------------------------
    # Help Command/Option Handler
    #------------------------------------------------------------------------------
    def help(self):
        if ( (self.option("--help")) or (self.cmd == "help") or (self.option("-h")) ):
            return True
        else:
            return False

    #------------------------------------------------------------------------------
    # Usage Command/Option Handler
    #------------------------------------------------------------------------------
    def usage(self):
        if ( (self.option("--usage")) or (self.cmd == "usage") ):
            return True
        else:
            return False

    #------------------------------------------------------------------------------
    # Version Command/Option Handler
    #------------------------------------------------------------------------------
    def version(self):
        if ( (self.option("--version")) or (self.cmd == "version") or (self.option("-v"))):
            return True
        else:
            return False

    #------------------------------------------------------------------------------
    # print the arguments with their corresponding argv list position to std out
    #------------------------------------------------------------------------------
    def show_args(self):
        x = 0
        for arg in self.argv:
            print("argv[" + str(x) + "] = " + arg)
            x = x + 1

#------------------------------------------------------------------------------
# [ Argument Class ]
#   all command line arguments (object inherited from Python list)
#------------------------------------------------------------------------------
class Argument(list):
    def __init__(self, argv):
        self.argv = argv
        list.__init__(self, self.argv)


    # return argument at position specified by the 'position' parameter
    def _getArg(self, position):
        if ( self.argv ) and ( len(self.argv) > position ):
            return self.argv[position]
        else:
            return ""

    # return position of user specified argument in the argument list
    def _getArgPosition(self, test_arg):
        if ( self.argv ):
            if test_arg in self.argv:
                return self.argv.index(test_arg)
            else:
                return -1

    # return the argument at the next position following a user specified positional argument (e.g. for argument to an option in cmd)
    def _getArgNext(self, position):
        if len(self.argv) > (position + 1):
            return self.argv[position + 1]
        else:
            return ""

#------------------------------------------------------------------------------
# [ Option Class ]
#   Command line options (object inherited from Python list)
#   Definition: string that begins with "-" (i.e. can be -h or --long)
#------------------------------------------------------------------------------
class Option(list):
    def __init__(self, argv):
        self.argv = argv
        list.__init__(self, self._make_option_list())

    # make a list of the options in the command (defined as anything that starts with "-" character)
    def _make_option_list(self):
        optargv = []
        for x in self.argv:
            if x.startswith("-"):
                optargv.append(x)
        return optargv
