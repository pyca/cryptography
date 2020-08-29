#!/usr/bin/env python
# encoding: utf-8

# VARS = app_name, developer, license_name, year
app_file_string = """
#!/usr/bin/env python
# encoding: utf-8

#------------------------------------------------------------------------------
# {{app_name}}
# Copyright {{year}} {{developer}}
# {{license}}
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------------
# c.cmd = Primary command ({{app_name}} <primary command>)
# c.cmd2 = Secondary command ({{app_name}} <primary command> <secondary command>)
#
# c.arg_to_cmd = first positional argument to the primary command
# c.arg_to_cmd2 = first positional argument to the secondary command
#
# c.option(option_string, [bool argument_required]) = test for option with optional positional argument to option test
# c.option_with_arg(option_string) = test for option and mandatory positional argument to option
# c.flag(flag_string) = test for presence of a "option=argument" style flag
#
# c.arg(arg_string) = returns the next positional argument to the arg_string argument
# c.flag_arg(flag_string) = returns the flag assignment for a "--option=argument" style flag
#------------------------------------------------------------------------------------

# Application start
def main():
    import sys
    from Naked.commandline import Command
    from Naked.toolshed.state import StateObject

    #------------------------------------------------------------------------------------------
    # [ Instantiate command line object ]
    #   used for all subsequent conditional logic in the CLI application
    #------------------------------------------------------------------------------------------
    c = Command(sys.argv[0], sys.argv[1:])
    #------------------------------------------------------------------------------
    # [ Instantiate state object ]
    #------------------------------------------------------------------------------
    state = StateObject()
    #------------------------------------------------------------------------------------------
    # [ Command Suite Validation ] - early validation of appropriate command syntax
    # Test that user entered at least one argument to the executable, print usage if not
    #------------------------------------------------------------------------------------------
    if not c.command_suite_validates():
        from {{app_name}}.settings import usage as {{app_name}}_usage
        print({{app_name}}_usage)
        sys.exit(1)
    #------------------------------------------------------------------------------------------
    # [ NAKED FRAMEWORK COMMANDS ]
    # Naked framework provides default help, usage, and version commands for all applications
    #   --> settings for user messages are assigned in the lib/{{app_name}}/settings.py file
    #------------------------------------------------------------------------------------------
    if c.help():      # User requested {{app_name}} help information
        from {{app_name}}.settings import help as {{app_name}}_help
        print({{app_name}}_help)
        sys.exit(0)
    elif c.usage():   # User requested {{app_name}} usage information
        from {{app_name}}.settings import usage as {{app_name}}_usage
        print({{app_name}}_usage)
        sys.exit(0)
    elif c.version(): # User requested {{app_name}} version information
        from {{app_name}}.settings import app_name, major_version, minor_version, patch_version
        version_display_string = app_name + ' ' + major_version + '.' + minor_version + '.' + patch_version
        print(version_display_string)
        sys.exit(0)
    #------------------------------------------------------------------------------------------
    # [ PRIMARY COMMAND LOGIC ]
    #   Enter your command line parsing logic below
    #------------------------------------------------------------------------------------------

    # [[ Example usage ]] ------------------------------->>>
    # if c.cmd == 'hello':
    #     if c.cmd2 = 'world':
    # 	      if c.option('--print'):
    # 		      print('Hello World!')
    # elif c.cmd == 'spam':
    #     if c.option_with_arg('--with'):
    # 		  friend_of_spam = c.arg('--with')    # user enters {{app_name}} spam --with eggs
    # 		  print('spam and ' + friend_of_spam) # prints 'spam and eggs'
    # elif c.cmd == 'naked':
    #     if c.flag("--language"):
    #         lang = c.flag_arg("--language")     # user enters {{app_name}} naked --language=python
    #         print("Naked & " + lang)            # prints 'Naked & python'
    # End example --------------------------------------->>>

    #------------------------------------------------------------------------------------------
    # [ DEFAULT MESSAGE FOR MATCH FAILURE ]
    #  Message to provide to the user when all above conditional logic fails to meet a true condition
    #------------------------------------------------------------------------------------------
    else:
        print("Could not complete the command that you entered.  Please try again.")
        sys.exit(1) #exit

if __name__ == '__main__':
    main()
"""
