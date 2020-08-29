#!/usr/bin/env python
# encoding: utf-8
# cython: profile=False

import os
import sys
import subprocess
from Naked.settings import debug as DEBUG_FLAG

#------------------------------------------------------------------------------
# [ execute function ] (boolean)
#  run a shell command and print std out / std err to terminal
#  returns True if exit status = 0
#  returns False if exit status != 0
#------------------------------------------------------------------------------
def execute(command):
    try:
        response = subprocess.call(command, shell=True)
        if response == 0:
            return True
        else:
            return False
    except subprocess.CalledProcessError as cpe:
        try:
            sys.stderr.write(cpe.output)
        except TypeError as te:
            sys.stderr.write(str(cpe.output))
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to run the shell command with the execute() function (Naked.toolshed.shell.py).")
        raise e


#------------------------------------------------------------------------------
# [ run function ] (bytes string or False)
#   run a shell command
#   default =
#       success:: print to std out and return the std out string
#         error:: print to stderr return False, suppress SystemExit on error to permit ongoing run of calling script
#   suppress_stdout = True >> suppress std output stream print (returns string)
#   suppress_stderr = True >> suppress std err stream print (returns False)
#   suppress_exit_status_call = False >> raise SystemExit with the returned status code
#------------------------------------------------------------------------------
def run(command, suppress_stdout=False, suppress_stderr=False, suppress_exit_status_call=True):
    try:
        response = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
        if not suppress_stdout:
            print(response)
        return response
    except subprocess.CalledProcessError as cpe:
        if not suppress_stderr: # error in existing application (non-zero exit status)
            try:
                sys.stderr.write(cpe.output)
            except TypeError as te: # deal with unusual errors from some system executables that return non string type through subprocess.check_output
                sys.stderr.write(str(cpe.output))
        if not suppress_exit_status_call:
            if cpe.returncode:
                sys.exit(cpe.returncode)
            else:
                sys.exit(1)
        return False # return False on non-zero exit status codes (i.e. failures in the subprocess executable)
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to run the shell command with the run() function (Naked.toolshed.shell.py).")
        raise e


#------------------------------------------------------------------------------
# [ muterun function ] (NakedObject with attributes for stdout, stderr, exitcode)
#  run a shell command and return a response object
#  return object attributes : stdout (bytes), stderr (bytes), exitcode (int)
#------------------------------------------------------------------------------
def muterun(command):
    try:
        from Naked.toolshed.types import NakedObject
        response_obj = NakedObject()
        response = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
        response_obj.stdout = response
        response_obj.exitcode = 0
        response_obj.stderr = b""
        return response_obj
    except subprocess.CalledProcessError as cpe:
        response_obj.stdout = b""
        response_obj.stderr = cpe.output
        if cpe.returncode:
            response_obj.exitcode = cpe.returncode
        else:
            response_obj.exitcode = 1
        return response_obj
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to run the shell command with the mute_run() function (Naked.toolshed.shell.py).")
        raise e


#------------------------------------------------------------------------------
# RUBY COMMAND EXECUTION
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# [ execute_rb function ] (boolean)
#  execute a ruby script file in a shell subprocess
#------------------------------------------------------------------------------
def execute_rb(file_path, arguments=""):
    try:
        if len(arguments) > 0:
            rb_command = 'ruby ' + file_path + " " + arguments
        else:
            rb_command = 'ruby ' + file_path
        return execute(rb_command) # return result of execute() of the ruby file
    except Exception as e:
        if DEBUG_FLAG:
             sys.stderr.write("Naked Framework Error: unable to run the shell command with the run_rb() function (Naked.toolshed.shell.py).")
        raise e

#------------------------------------------------------------------------------
# [ run_rb function ] (bytes string or False)
#  execute a ruby script file in a shell subprocess, return the output
#------------------------------------------------------------------------------
def run_rb(file_path, arguments="", suppress_stdout=False, suppress_stderr=False, suppress_exit_status_call=True):
    try:
        if len(arguments) > 0:
            rb_command = 'ruby ' + file_path + " " + arguments
        else:
            rb_command = 'ruby ' + file_path
        return run(rb_command, suppress_stdout, suppress_stderr, suppress_exit_status_call) # return result of run() of the ruby file
    except Exception as e:
        if DEBUG_FLAG:
             sys.stderr.write("Naked Framework Error: unable to run the shell command with the run_rb() function (Naked.toolshed.shell.py).")
        raise e

#------------------------------------------------------------------------------
# [ muterun_rb function ] (NakedObject response object)
#------------------------------------------------------------------------------
def muterun_rb(file_path, arguments=""):
    try:
        if len(arguments) > 0:
            rb_command = 'ruby ' + file_path + " " + arguments
        else:
            rb_command = 'ruby ' + file_path
        return muterun(rb_command) # return result of muterun() of the ruby file
    except Exception as e:
        if DEBUG_FLAG:
             sys.stderr.write("Naked Framework Error: unable to run the shell command with the muterun_rb() function (Naked.toolshed.shell.py).")
        raise e

#------------------------------------------------------------------------------
# NODE.JS COMMAND EXECUTION
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# [ execute_js function ] (boolean)
#  execute a node.js script file in a shell subprocess
#  stdout stream to terminal
#  returns True for success (=0) exit status code
#  returns False for unsuccessful (!=0) exit status code
#------------------------------------------------------------------------------
def execute_js(file_path, arguments=""):
    try:
        if len(arguments) > 0:
            js_command = 'node ' + file_path + " " + arguments
        else:
            js_command = 'node ' + file_path
        return execute(js_command) # return result of execute() of node.js file
    except Exception as e:
        if DEBUG_FLAG:
             sys.stderr.write("Naked Framework Error: unable to run the shell command with the run_js() function (Naked.toolshed.shell.py).")
        raise e
#------------------------------------------------------------------------------
# [ run_js function ] (byte string or False)
#  execute a node.js script file in a shell subprocess
#  print the standard output to the standard output stream by default
#  set suppress_output to True to suppress stream to standard output.  String is still returned to calling function
#  set suppress_exit_status_call to True to suppress raising sys.exit on failures with shell subprocess exit status code (if available) or 1 if not available
#  returns the standard output byte string from the subprocess executable on success
#  returns False if the subprocess exits with a non-zero exit code
#------------------------------------------------------------------------------
def run_js(file_path, arguments="", suppress_stdout=False, suppress_stderr=False, suppress_exit_status_call=True):
    try:
        if len(arguments) > 0:
            js_command = 'node ' + file_path + " " + arguments
        else:
            js_command = 'node ' + file_path
        return run(js_command, suppress_stdout, suppress_stderr, suppress_exit_status_call) # return result of run() of node.js file
    except Exception as e:
        if DEBUG_FLAG:
             sys.stderr.write("Naked Framework Error: unable to run the shell command with the run_js() function (Naked.toolshed.shell.py).")
        raise e

#------------------------------------------------------------------------------
# [ muterun_js function ] (NakedObject response object)
#------------------------------------------------------------------------------
def muterun_js(file_path, arguments=""):
    try:
        if len(arguments) > 0:
            js_command = 'node ' + file_path + " " + arguments
        else:
            js_command = 'node ' + file_path
        return muterun(js_command) # return result of muterun() of node.js file
    except Exception as e:
        if DEBUG_FLAG:
             sys.stderr.write("Naked Framework Error: unable to run the shell command with the muterun_js() function (Naked.toolshed.shell.py).")
        raise e

#------------------------------------------------------------------------------
# [ Environment Class ]
#   shell environment variables class
#   self.env = the environment variable dictionary
#   self.vars = the environment variable names list
#------------------------------------------------------------------------------
class Environment():
    def __init__(self):
        self.env = os.environ
        self.vars = list(os.environ.keys())

    #------------------------------------------------------------------------------
    # [ is_var method ] (boolean)
    #   return boolean for presence of a variable name in the shell environment
    #------------------------------------------------------------------------------
    def is_var(self, var_name):
        try:
            return (var_name in self.vars)
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: unable to determine if the variable is included in the shell variable list with the is_var() method (Naked.toolshed.shell).")
            raise e

    #------------------------------------------------------------------------------
    # [ get_var method ] (string)
    #   get the variable value for a variable in the shell environment list
    #   returns empty string if the variable is not included in the environment variable list
    #------------------------------------------------------------------------------
    def get_var(self, var_name):
        try:
            if var_name in self.vars:
                return self.env[var_name]
            else:
                return ""
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: unable to return the requested shell variable with the get_var() method (Naked.toolshed.shell).")
            raise e

    #------------------------------------------------------------------------------
    # [ get_split_var_list method ] (list of strings)
    #   return a list of strings split by OS dependent separator from the shell variable assigment string
    #   if the variable name is not in the environment list, returns an empty list
    #------------------------------------------------------------------------------
    def get_split_var_list(self, var_name):
        try:
            if var_name in self.vars:
                return self.env[var_name].split(os.pathsep)
            else:
                return []
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: unable to return environment variable list with the get_split_var_list() method (Naked.toolshed.shell).")
            raise e


if __name__ == '__main__':
    pass
    # e = Environment()
    # pathlist = e.get_split_var_list("PATH")
    # for item in pathlist:
    #   print(item)
