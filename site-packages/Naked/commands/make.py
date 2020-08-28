#!/usr/bin/env python
# encoding: utf-8

import Naked.toolshed.system as system
import Naked.toolshed.python as python
import Naked.toolshed.file as nfile
import Naked.toolshed.ink as ink
from Naked.toolshed.types import XDict, XString
from Naked.toolshed.system import make_dirs, make_path, exit_success
import datetime
import sys

## TODO: Check for a local settings file (appname.yaml)
## TODO: make directories and files
#------------------------------------------------------------------------------
# [ MakeController class ]
#   Top level logic for the make command
#------------------------------------------------------------------------------
class MakeController:
    def __init__(self, app_name):
        self.app_name = app_name

    def run(self):
        if self.app_name == None:
            i = InfoCompiler(None)
            data_container = i.getSetupFileInfo()
        else:
            i = InfoCompiler(self.app_name)
            data_container = i.getUserInfo()

        db = DirectoryBuilder(data_container)
        db.build()
        fb = FileBuilder(data_container)
        if fb.build_and_write(): # file writes were successful
            main_script_path = make_path(data_container.app_name, 'lib', data_container.app_name, 'app.py')
            settings_path = make_path(data_container.app_name, 'lib', data_container.app_name, 'settings.py')
            command_dir = make_path(data_container.app_name, 'lib', data_container.app_name, 'commands')
            setuppy_path = make_path(data_container.app_name, 'setup.py')
            print(" ")
            print(data_container.app_name + " was successfully built.")
            print(" ")
            print("-----")
            print("Main application script:  " + main_script_path)
            print("Settings file:  " + settings_path)
            print("Commands directory:  " + command_dir)
            print("setup.py file:  " + setuppy_path)
            print("-----")
            print(" ")
            print("Use 'python setup.py develop' from the top level of your project and you can begin testing your application with the executable, " + data_container.app_name)
            exit_success()
#------------------------------------------------------------------------------
# [ InfoCompiler class ]
#  obtain information from user in order to build a new project
#------------------------------------------------------------------------------
class InfoCompiler:
    def __init__(self, app_name):
        self.data = DataContainer()
        self.data.app_name = app_name
        self.displayed_info_flag = 0

    def getUserInfo(self):
        if not self.displayed_info_flag:
            print("We need some information to create your project.")
            self.displayed_info_flag = 1
        # If no project name, then query for it because this is mandatory
        if self.data.app_name == None:
            if python.is_py2:
                response = raw_input("Please enter your application name (q=quit): ")
            else:
                response = input("Please enter your application name (q=quit): ")
            if len(response) > 0:
                if response == "q":
                    print("Aborted project build.")
                    sys.exit(0) # user requested quit
                else:
                    if len(response.split()) > 1: # if more than one word
                        print("The application name must be a single word.  Please try again.")
                        self.getUserInfo()
                    else:
                        self.data.app_name = response
            else:
                print("The Naked project will not build without an application name.  Please try again.")
                return self.getUserInfo()
        # if project name already set, then obtain the other optional information
        if python.is_py2():
            self.data.developer = raw_input("Enter the licensing developer or organization (q=quit): ")
            if self.data.developer == "q":
                print("Aborted the project build.")
                sys.exit(0)
            self.data.license = raw_input("Enter the license type (or leave blank, q=quit): ")
            if self.data.license == "q":
                print("Aborted the project build.")
                sys.exit(0)
        else:
            self.data.developer = input("Enter the licensing developer or organization: ")
            if self.data.developer == "q":
                print("Aborted the project build.")
                sys.exit(0)
            self.data.license = input("Enter the license type (or leave blank): ")
            if self.data.license == "q":
                print("Aborted the project build.")
                sys.exit(0)
        if self.confirmData():
            return self.data
        else:
            print("Let's try again...")
            return self.getUserInfo() # try again

    def getSetupFileInfo(self):
        files = system.list_all_files_cwd()
        if len(files) > 0:
            setupfile_exists = False
            for a_file in files:
                if 'naked.yaml' == a_file.lower(): # accepts any permutation of upper/lower case 'naked.yaml'
                    print("Detected a Naked project YAML setup file (" + a_file + ").")
                    setupfile_exists = True
                    fr = nfile.FileReader(a_file)
                    the_yaml = fr.read_utf8()
                    self.parseYaml(the_yaml)
            if setupfile_exists:
                if self.confirmData():
                    return self.data
                else:
                    print("Aborted the project build.")
                    if python.is_py2():
                        response = raw_input("Would you like to modify this information? (y/n) ")
                    else:
                        response = input("Would you like to modify this information? (y/n) ")
                    if response in ['y', 'Y', 'Yes', 'YES', 'yes']:
                        self.displayed_info_flag = 1
                        self.data.app_name = None
                        return self.getUserInfo() # return the result from the getUserInfo command to the calling method
                    else:
                        sys.exit(0)
            else:
                return self.getUserInfo() # there are files but no setup file, use the manual entry method
        else:
            return self.getUserInfo() # there are no files in the directory, use the manual entry method


    def parseYaml(self, yaml_string):
        import yaml
        the_yaml = yaml.load(yaml_string)
        # Parse project name
        if 'application' in the_yaml:
            self.data.app_name = the_yaml['application']
        else:
            print("Unable to find the application name ('application' field) in naked.yaml")
            if python.is_py2:
                response = raw_input("Please enter your application name: ")
            else:
                response = input("Please enter your application name: ")
            if len(response) > 0:
                self.data.app_name = response # assign the application name at CL if was not entered in file
            else:
                print("The Naked project will not build without an application name.  Please try again.")
                self.displayed_info_flag = 1
                self.getUserInfo()
        # Parse developer
        if 'developer' in the_yaml:
            self.data.developer = the_yaml['developer'] # set developer
        else:
            self.data.developer = ""
        # Parse license type
        if 'license' in the_yaml:
            self.data.license = the_yaml['license'] # set license
        else:
            self.data.license = ""


    def confirmData(self):
        templ_str = getHeaderTemplate()
        template = ink.Template(templ_str)
        renderer = ink.Renderer(template, {'app_name': self.data.app_name, 'developer': self.data.developer, 'license': self.data.license, 'year': self.data.year})
        display_header = renderer.render()
        print("\nPlease confirm the information below:")
        print(display_header)

        if python.is_py2():
            response = raw_input("Is this correct? (y/n) ")
        else:
            response = input("Is this correct? (y/n) ")

        if response in ['y', 'Y', 'yes', 'YES']:
            return True
        else:
            self.data.app_name = None
            return False

#------------------------------------------------------------------------------
# [ getHeaderTemplate function ] (string)
#  returns the Ink header template for user confirmation
#------------------------------------------------------------------------------
def getHeaderTemplate():
    templ_str = """
----------------------------------------------------------
 {{app_name}}
 Copyright {{year}} {{developer}}
 {{license}}
----------------------------------------------------------
    """
    return templ_str

#------------------------------------------------------------------------------
# [ DataContainer class ]
#   state maintenance object that holds project information
#------------------------------------------------------------------------------
class DataContainer:
    def __init__(self):
        self.cwd = system.cwd()
        self.year = str(datetime.datetime.now().year)

#------------------------------------------------------------------------------
# [ DirectoryBuilder class ]
#   generation of directory structure for a new project
#------------------------------------------------------------------------------
class DirectoryBuilder:
    def __init__(self, data_container):
        self.data_container = data_container

    def build(self):
        top_level_dir = self.data_container.app_name
        second_level_dirs = ['docs', 'lib', 'tests']
        lib_subdir = make_path(self.data_container.app_name, 'commands')

        for xdir in second_level_dirs:
            make_dirs(make_path(top_level_dir, xdir))

        make_dirs(make_path(top_level_dir, 'lib', lib_subdir))

#------------------------------------------------------------------------------
# [ FileBuilder class ]
#  generate the files for a new project
#------------------------------------------------------------------------------
class FileBuilder:
    def __init__(self, data_container):
        self.data_container = data_container
        self.file_dictionary = {}

    def build_and_write(self):
        self._make_file_paths()      # create the file paths for all generated files
        self._render_file_strings()  # create the rendered template strings
        self._make_file_dictionary() # make the file path : file string dictionary
        self.write_files()           # write out to files
        return True                  # if made it this far without exception, return True to calling method to confirm file writes

    # files are included in self.file_dictionary as key = filepath, value = filestring pairs
    #  write the files to disk
    def write_files(self):
        the_file_xdict = XDict(self.file_dictionary)
        for filepath, file_string in the_file_xdict.xitems():
            fw = nfile.FileWriter(filepath)
            try:
                fw.write_utf8(file_string)
            except TypeError as te: # catch unicode write errors
                fw.write(file_string)

    def _make_file_paths(self):
        from Naked.toolshed.system import make_path

        self.top_manifestin = make_path(self.data_container.app_name, 'MANIFEST.in')
        self.top_readmemd = make_path(self.data_container.app_name, 'README.md')
        self.top_setupcfg = make_path(self.data_container.app_name, 'setup.cfg')
        self.top_setuppy = make_path(self.data_container.app_name, 'setup.py')
        self.docs_license = make_path(self.data_container.app_name, 'docs', 'LICENSE')
        self.docs_readmerst = make_path(self.data_container.app_name, 'docs', 'README.rst')
        self.lib_initpy = make_path(self.data_container.app_name, 'lib', '__init__.py')
        self.com_initpy = make_path(self.data_container.app_name, 'lib', self.data_container.app_name, 'commands', '__init__.py')
        self.tests_initpy = make_path(self.data_container.app_name, 'tests', '__init__.py')
        self.lib_profilerpy = make_path(self.data_container.app_name, 'lib', 'profiler.py')
        self.lib_proj_initpy = make_path(self.data_container.app_name, 'lib', self.data_container.app_name, '__init__.py')
        self.lib_proj_apppy = make_path(self.data_container.app_name, 'lib', self.data_container.app_name, 'app.py')
        self.lib_proj_settingspy = make_path(self.data_container.app_name, 'lib', self.data_container.app_name, 'settings.py')

    def _render_file_strings(self):
        from Naked.templates.manifest_in_file import manifest_file_string
        from Naked.templates.readme_md_file import readme_md_string
        from Naked.templates.setup_cfg_file import setup_cfg_string
        from Naked.templates.setup_py_file import setup_py_string
        from Naked.templates.profiler_file import profiler_file_string
        from Naked.templates.app_file import app_file_string
        from Naked.templates.settings_file import settings_file_string

        data_dict = self.data_container.__dict__

        self.top_manifestin_rendered = manifest_file_string # no replacements necessary
        self.top_readmemd_rendered = self._render_template(self._create_template(readme_md_string), data_dict) #requires app_name replacement
        self.top_setupcfg_rendered = setup_cfg_string # no replacement necessary
        self.top_setuppy_rendered = self._render_template(self._create_template(setup_py_string), data_dict) # requires app_name, developer replacements
        self.docs_readmerst_rendered = "" # blank document stub write
        self.lib_profilerpy_rendered = profiler_file_string # no replacement necessary
        self.initpy_rendered = "" # blank __init__.py files
        self.lib_proj_apppy_rendered = self._render_template(self._create_template(app_file_string), data_dict) # requires app_name, developer, license_name, year replacements
        self.lib_proj_settingspy_rendered = self._render_template(self._create_template(settings_file_string), data_dict) # requires app_name replacement

        if len(self.data_container.license) > 0:
            license = self.parse_licenses(self.data_container.license) # find the appropriate license template if the license was provided by user
            if len(license) > 0: # could be empty string if fails to match a license template provided by Naked
                self.docs_license_rendered = self._render_template(self._create_template(license), data_dict)
        else:
            self.docs_license_rendered = ""

    def _make_file_dictionary(self):
        file_dictionary = {}
        ## File path : file string key/value pairs > make as XString and encode as unicode for unicode file writes
        file_dictionary[self.top_manifestin] = XString(self.top_manifestin_rendered).unicode().strip()
        file_dictionary[self.top_readmemd] = XString(self.top_readmemd_rendered).unicode().strip()
        file_dictionary[self.top_setupcfg] = XString(self.top_setupcfg_rendered).unicode().strip()
        file_dictionary[self.top_setuppy] = XString(self.top_setuppy_rendered).unicode().strip()
        file_dictionary[self.docs_license] = XString(self.docs_license_rendered).unicode().strip()
        file_dictionary[self.docs_readmerst] = XString(self.docs_readmerst_rendered).unicode().strip()
        file_dictionary[self.lib_initpy] = XString(self.initpy_rendered).unicode().strip()
        file_dictionary[self.com_initpy] = XString(self.initpy_rendered).unicode().strip()
        file_dictionary[self.tests_initpy] = XString(self.initpy_rendered).unicode().strip()
        file_dictionary[self.lib_profilerpy] = XString(self.lib_profilerpy_rendered).unicode().strip()
        file_dictionary[self.lib_proj_initpy] = XString(self.initpy_rendered).unicode().strip()
        file_dictionary[self.lib_proj_apppy] = XString(self.lib_proj_apppy_rendered).unicode().strip()
        file_dictionary[self.lib_proj_settingspy] = XString(self.lib_proj_settingspy_rendered).unicode().strip()

        self.file_dictionary = file_dictionary

    def _create_template(self, template_string):
        return ink.Template(template_string)

    def _render_template(self, template, key_dict):
        r = ink.Renderer(template, key_dict)
        return r.render()

    def parse_licenses(self, license_string):
        if len(license_string) > 0:
            license = license_string.lower() # case insensitive matching, make lower case version

            if license.startswith('apache'):
                from Naked.templates.licenses import apache_license
                return apache_license
            elif license.startswith('bsd'):
                from Naked.templates.licenses import bsd_license
                return bsd_license
            elif license.startswith('gpl'):
                from Naked.templates.licenses import gpl3_license
                return gpl3_license
            elif license.startswith('lgpl'):
                from Naked.templates.licenses import lgpl_license
                return lgpl_license
            elif license.startswith('mit'):
                from Naked.templates.licenses import mit_license
                return mit_license
            elif license.startswith('mozilla'):
                from Naked.templates.licenses import mozilla_license
                return mozilla_license
        else:
            return ""

def help():
    from Naked.toolshed.system import exit_success
    help_string = """
Naked make Command Help
=======================
The make command builds a new Naked project.  The project can be built from either responses that you give on the command line, or from a naked.yaml project settings file.

USAGE
  naked make [argument]

The command should be run in the top level of the path where you would like to create your project.  The argument to the make command is optional.  If used, this is the name of your new project.  It is not necessary to include the argument if you use a naked.yaml project settings file.

The naked.yaml settings file has the following structure:

  application:  <your project name>
  developer:    <developer name>
  license:      <license type>

Place this in the top level of an empty directory and use `naked make` in the same directory.  Naked will confirm your settings and then build the project directories and files from these settings.

SECONDARY COMMANDS
  none

OPTIONS
  none

EXAMPLES
  naked make
  naked make testapp"""
    print(help_string)
    exit_success()


if __name__ == '__main__':
    pass
