#!/usr/bin/env python
# encoding: utf-8

from Naked.commandline import Command
from Naked.toolshed.system import exit_success
import shlex

class Args:
    def __init__(self, command_string):
        self.com_string = command_string

    def run(self):
        cmd_list = shlex.split(self.com_string)
        c = Command(cmd_list[0], cmd_list[1:])
        print(' ')
        print("•naked• Assuming that your Command object is instantiated as an instance named 'c', the command that you entered would be parsed as follows:")
        print(' ')
        print('Application')
        print('-----------')
        print('c.app = ' + c.app)
        print(' ')
        print('Argument List Length')
        print('--------------------')
        print('c.argc = ' + str(c.argc))
        print(' ')
        print('Argument List Items')
        print('-------------------')
        print('c.argobj = ' + str(c.argobj))
        print(' ')
        print('Arguments by Zero Indexed Start Position')
        print('----------------------------------------')
        print('c.arg0 = ' + c.arg0)
        print('c.arg1 = ' + c.arg1)
        print('c.arg2 = ' + c.arg2)
        print('c.arg3 = ' + c.arg3)
        print('c.arg4 = ' + c.arg4)
        print(' ')
        print('Arguments by Named Position')
        print('---------------------------')
        print('c.first = ' + c.first)
        print('c.second = ' + c.second)
        print('c.third = ' + c.third)
        print('c.fourth = ' + c.fourth)
        print('c.fifth = ' + c.fifth)
        print(' ')
        print('Last Positional Argument')
        print('------------------------')
        print('c.arglp = ' + c.arglp)
        print('c.last = ' + c.last)
        print(' ')
        print('Primary & Secondary Commands')
        print('----------------------------')
        print('c.cmd = ' + c.cmd)
        print('c.cmd2 = ' + c.cmd2)
        print(' ')
        print('Option Exists Tests')
        print('------------------')
        print('c.option_exists() = ' + str(c.option_exists()))
        print('c.options = ' + str(c.options))
        print(' ')
        print('Option Argument Assignment')
        print('--------------------------')
        if c.option_exists(): # if there are options, iterate through and print arguments to them
            non_flag_options = False
            for x in range(len(c.optobj)):
                if '=' in c.optobj[x]:
                    continue # don't print flags, they are handled below
                else:
                    print('c.arg("' + c.optobj[x] + '") = ' + c.arg(c.optobj[x]))
                    non_flag_options = True
            if not non_flag_options:
                print("There are no short or long options in the command.")
        else: # otherwise, inform user that there are no options
            print("There are no short options, long options, or flags in your command.")
        print(' ')
        print('Flag Exists Tests')
        print('----------------')
        print('c.flag_exists() = ' + str(c.flag_exists()))
        print('c.flags = ' + str(c.flags))
        print(' ')
        print('Flag Argument Assignment')
        print('------------------------')
        if c.flag_exists():
            for y in c.optobj:
                if '=' in y:
                    the_flag = y.split('=')[0]
                    print('c.flag_arg("' + the_flag + '") = ' + c.flag_arg(the_flag))
        else: # provide message if there are no flags
            print("There are no flag style arguments (--flag=argument) in your command.")
        exit_success()


#------------------------------------------------------------------------------
# [ help function ] - help for the where command
#------------------------------------------------------------------------------
def help():
    from Naked.toolshed.system import exit_success
    help_string = """
Naked args Command Help
=======================
The args command displays information about the data that are parsed from a command string to Command object attributes and that are obtained from Command object methods.  It is intended to help with the design of your application logic when you use the Naked command line parser.

USAGE
  naked args '<command statement>'

The command statement is a mandatory argument to the command.  It should include a complete command as it would be entered on the command line, including the executable.  The argument should be completely enclosed within quotes.

SECONDARY COMMANDS
  none

OPTIONS
  none

EXAMPLE
  naked args 'testapp save somestring --unicode -s --name=file.txt'"""
    print(help_string)
    exit_success()

if __name__ == '__main__':
	pass
