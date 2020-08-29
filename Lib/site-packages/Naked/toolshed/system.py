#!/usr/bin/env python
# encoding: utf-8

import sys
import os
from Naked.settings import debug as DEBUG_FLAG

#------------------------------------------------------------------------------
#
# FILE & DIRECTORY PATHS
#
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# [ filename function ] (string)
#   returns file name from a file path (including the file extension)
#   Tests: test_SYSTEM.py :: test_sys_filename
#------------------------------------------------------------------------------
def filename(filepath):
    try:
        return os.path.basename(filepath)
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to return base filename from filename() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
# [ file_extension function ] (string)
#   returns file extension from a filepath
#   Tests: test_SYSTEM.py :: test_sys_file_extension
#------------------------------------------------------------------------------
def file_extension(filepath):
    try:
        return os.path.splitext(filepath)[1]
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to return file extension with file_extension() function (Naked.toolshed.system).")
        raise e


#------------------------------------------------------------------------------
# [ directory function ] (string)
#  returns directory path to the filepath
#  Tests: test_SYSTEM.py :: test_sys_dir_path
#------------------------------------------------------------------------------
def directory(filepath):
    try:
        return os.path.dirname(filepath)
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to return directory path to file with directory() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
#  [ make_path function ] (string)
#   returns OS independent file path from tuple of path components
#   Tests: test_SYSTEM.py :: test_sys_make_filepath
#------------------------------------------------------------------------------
def make_path(*path_list):
    try:
        return os.path.join(*path_list)
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to make OS independent path with the make_path() function (Naked.toolshed.system).")
        raise e


#------------------------------------------------------------------------------
#  [ currentdir_to_basefile decorator function ] (returns decorated original function)
#    concatenates the absolute working directory path to the basename of file in the first parameter of the undecorated function
#    Tests: test_SYSTEM.py :: test_sys_add_currentdir_path_to_basefile
#------------------------------------------------------------------------------
def currentdir_to_basefile(func):
    try:
        from functools import wraps

        @wraps(func)
        def wrapper(file_name, *args, **kwargs):
            current_directory = os.getcwd() #get current working directory path
            full_path = os.path.join(current_directory, file_name) # join cwd path to the filename for full path
            return func(full_path, *args, **kwargs) #return the original function with the full path to file as first argument
        return wrapper
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: error with the currentdir_to_basefile() decorator function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
# [ currentdir_firstparam decorator function ] (returns decorated original function)
#   adds the current working directory as the first function parameter of the decorated function
#   Tests: test_SYSTEM.py :: test_sys_add_currentdir_path_first_arg
#------------------------------------------------------------------------------
def currentdir_firstparam(func):
    try:
        from functools import wraps

        @wraps(func)
        def wrapper(dir="", *args, **kwargs):
            current_directory = os.getcwd()
            return func(current_directory, *args, **kwargs)
        return wrapper
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: error with the currentdir_firstargument() decorator function (Naked.toolshed.system).")
        raise e


#------------------------------------------------------------------------------
# [ currentdir_lastargument decorator function ] (returns decorated original function)
#   adds the current working directory as the last function parameter of the decorated function
#   Note: you cannot use other named arguments in the original function with this decorator
#   Note: the current directory argument in the last position must be named current_dir
#   Tests: test_SYSTEM.py :: test_sys_add_currentdir_last_arg
#------------------------------------------------------------------------------
def currentdir_lastparam(func):
    try:
        from functools import wraps

        @wraps(func)
        def wrapper(*args, **kwargs):
            the_cwd = os.getcwd()
            return func(*args, current_dir=the_cwd)
        return wrapper
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: error with the currentdir_lastargument() decorator function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
#  [ fullpath function ] (string)
#    returns the absolute path to a file that is in the current working directory
#    file_name = the basename of the file in the current working directory
#       Example usage where test.txt is in working directory:
#           filepath = fullpath("test.txt")
#    Tests: test_SYSTEM.py :: test_sys_full_path_to_file
#------------------------------------------------------------------------------
@currentdir_to_basefile # current directory decorator - adds the directory path up to the filename to the basefile name argument to original function
def fullpath(file_name):
    try:
        return file_name
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to return absolute path to the file with the fullpath() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
# [ cwd function ] (string)
#   returns the current working directory path
#   does not need to be called with an argument, the decorator assigns it
#       Example usage:
#           current_dir = cwd()
#   Tests: test_SYSTEM.py :: test_sys_cwd_path
#------------------------------------------------------------------------------
@currentdir_firstparam
def cwd(dir=""):
    try:
        return dir
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to return the current working directory with the cwd() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
#
# DIRECTORY WRITES
#
#------------------------------------------------------------------------------

## TODO: add tests
#------------------------------------------------------------------------------
# [ make_dirs function ] (--none--)
#  make a new directory path (recursive if multiple levels of depth) if it
#  DOES NOT already exist
#------------------------------------------------------------------------------
def make_dirs(dirpath):
    try:
        import os
        import errno
        os.makedirs(dirpath)
        return True
    except OSError as ose:
        if ose.errno != errno.EEXIST: # directory already exists
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Could not write the directory path passed as an argument to the make_dirs() function (Naked.toolshed.system).")
            raise ose
        else:
            return False
    except Exception as e:
        raise e

#------------------------------------------------------------------------------
#
# FILE & DIRECTORY TESTING
#
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# [ file_exists function ] (boolean)
#  return boolean for existence of file in specified path
#  Tests: test_SYSTEM.py :: test_file_exists
#------------------------------------------------------------------------------
def file_exists(filepath):
    try:
        if os.path.exists(filepath) and os.path.isfile(filepath): # test that exists and is a file
            return True
        else:
            return False
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: error with test for the presence of the file with the file_exists() method (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
# [ is_file function ] (boolean)
#  returns boolean for determination of whether filepath is a file
#  Tests: test_SYSTEM.py :: test_sys_is_file, test_sys_is_file_missing_file,
#        test_sys_is_file_when_dir
#------------------------------------------------------------------------------
def is_file(filepath):
    try:
        return os.path.isfile(filepath)
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: error with test for file with the is_file() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
# [ dir_exists function ] (boolean)
#   return boolean for existence of directory in specified path
#   Tests: test_SYSTEM.py :: test_dir_exists, test_dir_exists_missing_dir
#------------------------------------------------------------------------------
def dir_exists(dirpath):
    try:
        if os.path.exists(dirpath) and os.path.isdir(dirpath): # test that exists and is a directory
            return True
        else:
            return False
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: error with test for directory with the dir_exists() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
# [ is_dir function ] (boolean)
#   returns boolean for determination of whether dirpath is a directory
#   Tests: test_SYSTEM.py :: test_sys_dir_is_dir, test_sys_dir_is_dir_when_file,
#           test_sys_dir_is_dir_when_missing
#------------------------------------------------------------------------------
def is_dir(dirpath):
    try:
        return os.path.isdir(dirpath)
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: error with test for directory with the is_dir() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
#
# FILE METADATA
#
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# [ filesize function ] (int)
#   return file size in bytes
#   Tests: test_SYSTEM.py :: test_sys_meta_file_size
#------------------------------------------------------------------------------
def file_size(filepath):
    try:
        return os.path.getsize(filepath)
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to return file size with the file_size() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
# [ file_mod_time function ] (string)
#   return the last file modification date/time
#   Tests: test_SYSTEM.py :: test_sys_meta_file_mod
#------------------------------------------------------------------------------
def file_mod_time(filepath):
    try:
        import time
        return time.ctime(os.path.getmtime(filepath))
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to return file modification data with the file_mod_time() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
#
# FILE LISTINGS
#
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# [ list_all_files function ] (list)
#   returns a list of all files in developer specified directory
#   Tests: test_SYSTEM.py :: test_sys_list_all_files, test_sys_list_all_files_emptydir
#------------------------------------------------------------------------------
def list_all_files(dir):
    try:
        filenames = [name for name in os.listdir(dir) if os.path.isfile(os.path.join(dir, name))]
        return filenames
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to generate directory file list with the list_all_files() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
# [ list_filter_files function ] (list)
#   returns a list of files filtered by developer defined file extension in developer defined directory
#       Usage example:
#           filenames = list_filter_files("py", "tests")
#   Tests: test_SYSTEM.py :: test_sys_list_filter_files, test_sys_list_filter_files_nomatch
#------------------------------------------------------------------------------
def list_filter_files(extension_filter, dir):
    try:
        if not extension_filter.startswith("."):
            extension_filter = "." + extension_filter
        filenames = [name for name in os.listdir(dir) if name.endswith(extension_filter)]
        return filenames
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to return list of filtered files with the list_filter_files() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
# [ list_all_files_cwd function ] (list)
#   returns a list of all files in the current working directory
#   Note: does not require argument, the decorator assigns the cwd
#       Usage example:
#           file_list = list_all_files_cwd()
#   Tests: test_SYSTEM.py :: test_sys_list_all_files_cwd
#------------------------------------------------------------------------------
@currentdir_firstparam
def list_all_files_cwd(dir=""):
    try:
        return list_all_files(dir)
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to return list of all files in current working directory with the list_all_files_cwd() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
# [ list_filter_files_cwd function ] (list)
#   returns a list of all files in the current working directory filtered by developer specified file extension
#   Note: do not specify the second argument, decorator assigns it
#       Usage example:
#           file_list = list_filter_files_cwd(".py")
#   Tests: test_SYSTEM.py :: test_sys_filter_files_cwd, test_sys_filter_files_cwd_nomatch
#------------------------------------------------------------------------------
@currentdir_lastparam
def list_filter_files_cwd(extension_filter, current_dir=""):
    try:
        return list_filter_files(extension_filter, current_dir)
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to return list of filtered files in current working directory with the list_filter_files_cwd() function (Naked.toolshed.system).")
        raise e


#------------------------------------------------------------------------------
# [ list_match_files function ] (list)
#   returns a list of all files that match the developer specified wildcard match pattern
#   can optionally specify return of full path to the files (rather than relative path from cwd) by setting full_path to True
#       Usage examples:
#           file_list = list_match_files("*.py")
#           file_list_fullpath = list_match_files("*.py", True)
#   Tests: test_SYSTEM.py :: test_sys_match_files, test_sys_match_files_fullpath
#------------------------------------------------------------------------------
def list_match_files(match_pattern, full_path = False):
    try:
        from glob import glob
        filenames = glob(match_pattern)
        if full_path:
            filenames_fullpath = []
            cwd = os.getcwd()
            for name in filenames:
                name = os.path.join(cwd, name) #make the full path to the file
                filenames_fullpath.append(name) #add to the new list
            return filenames_fullpath #then return that list
        else:
            return filenames
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to return list of matched files with the list_match_files() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
#
# SYMBOLIC LINK TESTING
#
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# [ is_link function ] (boolean)
#   return boolean indicating whether the path is a symbolic link
#------------------------------------------------------------------------------
def is_link(filepath):
    try:
        return os.path.islink(filepath)
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to determine whether path is a symbolic link with the is_link() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
# [ real_path function ] (string)
#   return the real file path pointed to by a symbolic link
#------------------------------------------------------------------------------
def real_path(filepath):
    try:
        return os.path.realpath(filepath)
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to return real path for symbolic link with the real_path() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
#
# DATA STREAMS
#
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# [ stdout function ]
#   print to std output stream
#------------------------------------------------------------------------------
def stdout(text):
    try:
        print(text)
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to print to the standard output stream with the stdout() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
# [ stdout_xnl function ]
#   print to std output stream without a newline
#------------------------------------------------------------------------------
def stdout_xnl(text):
    try:
        sys.stdout.write(text)
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to print to the standard output stream with the stdout_xnl() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
# [ stdout_iter function ]
#   print items in an iterable to the standard output stream with newlines after each string
#------------------------------------------------------------------------------
def stdout_iter(iter):
    try:
        for x in iter:
            stdout(x)
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to print to the standard output stream with the stdout_iter() function (Naked.toolshed.system).")
        raise e


#------------------------------------------------------------------------------
# [ stdout_iter_xnl function ]
#   print items in an iterable to the standard output stream without newlines after each string
#------------------------------------------------------------------------------
def stdout_iter_xnl(iter):
    try:
        for x in iter:
            stdout_xnl(x)
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to print to the standard output stream with the stdout_iter() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
# [ stderr function ]
#   print to std error stream
#   optionally (i.e. if exit = nonzero integer) permits exit from application with developer defined exit code
#------------------------------------------------------------------------------
def stderr(text, exit=0):
    try:
        sys.stderr.write(text + "\n")
        if exit:
            raise SystemExit(exit)
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to print to the standard error stream with the stderr() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
# [ stderr_xnl function ]
#  print to the standard error stream without a newline character after the `text` string
#------------------------------------------------------------------------------
def stderr_xnl(text, exit=0):
    try:
        sys.stderr.write(text)
        if exit:
            raise SystemExit(exit)
    except Exception as e:
        if DEBUG_FLAG:
            sys.stderr.write("Naked Framework Error: unable to print to the standard error stream with the stderr() function (Naked.toolshed.system).")
        raise e

#------------------------------------------------------------------------------
#
# APPLICATION CONTROL
#
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# [ exit_with_status function ]
#   application exit with developer specified exit status code (default = 0)
#   use an exit status integer argument
#   Tests: test_SYSTEM.py :: test_sys_exit_with_code
#------------------------------------------------------------------------------
def exit_with_status(exit=0):
    raise SystemExit(exit)

#------------------------------------------------------------------------------
# [ exit_fail function ]
#   application exit with status code 1
#   Tests: test_SYSTEM.py :: test_sys_exit_failure
#------------------------------------------------------------------------------
def exit_fail():
    raise SystemExit(1)

#------------------------------------------------------------------------------
# [ exit_success function]
#   application exit with status code 0
#   Tests: test_SYSTEM.py :: test_sys_exit_success
#------------------------------------------------------------------------------
def exit_success():
    raise SystemExit(0)



if __name__ == '__main__':
    pass
    # #------------------------------------------------------------------------------
    # # Standard Output Tests
    # #------------------------------------------------------------------------------
    # stdout("This is a test")
    # for x in range(10):
    #   stdout_xnl(str(x) + " ")
    # list_ten = ['10% ', '20% ', '30% ', '40% ', '50% ', '60% ', '70% ', '80% ', '90% ', '100%']
    # stdout_iter(list_ten)
    # #------------------------------------------------------------------------------
    # # Standard Error Tests
    # #------------------------------------------------------------------------------
    # stderr("This is a test")
    # stderr("This is a test", 1) #exit with status code 1
