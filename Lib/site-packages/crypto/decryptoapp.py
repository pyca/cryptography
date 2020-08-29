#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ------------------------------------------------------------------------------
# decrypto
# Copyright 2015 Christopher Simpkins
# MIT license
# ------------------------------------------------------------------------------

# Application start
def main():
    import os
    import sys
    from time import sleep
    import getpass
    import tarfile
    from Naked.commandline import Command
    from Naked.toolshed.shell import execute, muterun
    from Naked.toolshed.system import dir_exists, file_exists, list_all_files, make_path, stdout, stderr, is_dir
    from shellescape import quote

    # ------------------------------------------------------------------------------------------
    # [ Instantiate command line object ]
    #   used for all subsequent conditional logic in the CLI application
    # ------------------------------------------------------------------------------------------
    c = Command(sys.argv[0], sys.argv[1:])
    # ------------------------------------------------------------------------------------------
    # [ VALIDATION LOGIC ] - early validation of appropriate command syntax
    # Test that user entered at least one argument to the executable, print usage if not
    # ------------------------------------------------------------------------------------------
    if not c.command_suite_validates():
        from crypto.settings import usage as crypto_usage
        print(crypto_usage)
        sys.exit(1)
    # ------------------------------------------------------------------------------------------
    # [ HELP, VERSION, USAGE LOGIC ]
    # Naked framework provides default help, usage, and version commands for all applications
    #   --> settings for user messages are assigned in the lib/crypto/settings.py file
    # ------------------------------------------------------------------------------------------
    if c.help():      # User requested crypto help information
        from crypto.settings import help as crypto_help
        print(crypto_help)
        sys.exit(0)
    elif c.usage():   # User requested crypto usage information
        from crypto.settings import usage as crypto_usage
        print(crypto_usage)
        sys.exit(0)
    elif c.version():  # User requested crypto version information
        from crypto.settings import app_name, major_version, minor_version, patch_version
        version_display_string = app_name + ' ' + major_version + '.' + minor_version + '.' + patch_version
        print(version_display_string)
        sys.exit(0)
    # ------------------------------------------------------------------------------------------
    # [ APPLICATION LOGIC ]
    #
    # ------------------------------------------------------------------------------------------
    elif c.argc > 1:
        # code for multi-file processing and commands that include options
        use_standard_output = False  # print to stdout flag
        use_file_overwrite = False  # overwrite existing file
        untar_archives = True  # untar decrypted tar archives, true by default

        # set user option flags
        if c.option('--stdout') or c.option('-s'):
            use_standard_output = True
        if c.option('--overwrite') or c.option('-o'):
            use_file_overwrite = True
        if c.option('--nountar'):
            untar_archives = False

        directory_list = []  # directory paths included in the user entered paths from the command line
        file_list = []  # file paths included in the user entered paths from the command line (and inside directories entered)

        for argument in c.argv:
            if file_exists(argument):  # user included a file, add it to the file_list for decryption
                if argument.endswith('.crypt'):
                    file_list.append(argument)  # add .crypt files to the list of files for decryption
                elif argument.endswith('.gpg'):
                    file_list.append(argument)
                elif argument.endswith('.asc'):
                    file_list.append(argument)
                elif argument.endswith('.pgp'):
                    file_list.append(argument)
                else:
                    # cannot identify as an encrypted file, give it a shot anyways but warn user
                    file_list.append(argument)
                    stdout("Could not confirm that '" + argument + "' is encrypted based upon the file type.  Attempting decryption.  Keep your fingers crossed...")
            elif dir_exists(argument):  # user included a directory, add it to the directory_list
                directory_list.append(argument)
            else:
                if argument[0] == "-":
                    pass  # if it is an option, do nothing
                else:
                    stderr("'" + argument + "' does not appear to be an existing file or directory.  Aborting decryption attempt for this request.")

        # unroll the contained directory files into the file_list IF they are encrypted file types
        if len(directory_list) > 0:
            for directory in directory_list:
                directory_file_list = list_all_files(directory)
                for contained_file in directory_file_list:
                    if contained_file.endswith('.crypt'):
                        file_list.append(make_path(directory, contained_file))  # include the file with a filepath 'directory path/contained_file path'
                    elif contained_file.endswith('.gpg'):
                        file_list.append(make_path(directory, contained_file))
                    elif contained_file.endswith('asc'):
                        file_list.append(make_path(directory, contained_file))
                    elif contained_file.endswith('.pgp'):
                        file_list.append(make_path(directory, contained_file))

        # confirm that there are files for decryption, if not abort
        if len(file_list) == 0:
            stderr("Could not identify files for decryption")
            sys.exit(1)

        # get passphrase used to symmetrically decrypt the file
        passphrase = getpass.getpass("Please enter your passphrase: ")
        if len(passphrase) == 0:  # confirm that user entered a passphrase
                stderr("You did not enter a passphrase. Please repeat your command and try again.")
                sys.exit(1)
        passphrase_confirm = getpass.getpass("Please enter your passphrase again: ")

        if passphrase == passphrase_confirm:
            # begin decryption of each requested file.  the directory path was already added to the file path above
            for encrypted_file in file_list:
                # create the decrypted file name
                decrypted_filename = ""
                if encrypted_file.endswith('.crypt'):
                    decrypted_filename = encrypted_file[0:-6]
                elif encrypted_file.endswith('.gpg') or encrypted_file.endswith('.asc') or encrypted_file.endswith('.pgp'):
                    decrypted_filename = encrypted_file[0:-4]
                else:
                    decrypted_filename = encrypted_file + '.decrypt'  # if it was a file without a known encrypted file type, add the .decrypt suffix

                # determine whether file overwrite will take place with the decrypted file
                skip_file = False  # flag that indicates this file should not be encrypted
                created_tmp_files = False
                if not use_standard_output:  # if not writing a file, no need to check for overwrite
                    if file_exists(decrypted_filename):
                        if use_file_overwrite:  # rename the existing file to temp file which will be erased or replaced (on decryption failures) below
                            tmp_filename = decrypted_filename + '.tmp'
                            os.rename(decrypted_filename, tmp_filename)
                            created_tmp_files = True
                        else:
                            stdout("The file path '" + decrypted_filename + "' already exists.  This file was not decrypted.")
                            skip_file = True

                # begin decryption
                if not skip_file:
                    if use_standard_output:  # using --quiet flag to suppress stdout messages from gpg, just want the file data in stdout stream
                        system_command = "gpg --batch --quiet --passphrase " + quote(passphrase) + " -d " + quote(encrypted_file)
                        successful_execution = execute(system_command)  # use naked execute function to directly push to stdout, rather than return stdout

                        if not successful_execution:
                            stderr("Unable to decrypt file '" + encrypted_file + "'", 0)
                            if created_tmp_files:  # restore the moved tmp file to original if decrypt failed
                                tmp_filename = decrypted_filename + '.tmp'
                                if file_exists(tmp_filename):
                                    os.rename(tmp_filename, decrypted_filename)
                        else:  # decryption successful but we are in stdout flag so do not include any other output from decrypto
                            pass
                    else:
                        system_command = "gpg --batch -o " + quote(decrypted_filename) + " --passphrase " + quote(passphrase) + " -d " + quote(encrypted_file)
                        response = muterun(system_command)

                        if response.exitcode == 0:
                            stdout("'" + encrypted_file + "' decrypted to '" + decrypted_filename + "'")
                        else:  # failed decryption
                            if created_tmp_files:  # restore the moved tmp file to original if decrypt failed
                                tmp_filename = decrypted_filename + '.tmp'
                                if file_exists(tmp_filename):
                                    os.rename(tmp_filename, decrypted_filename)
                            # report the error
                            stderr(response.stderr)
                            stderr("Decryption failed for " + encrypted_file)

                # cleanup: remove the tmp file
                if created_tmp_files:
                    tmp_filename = decrypted_filename + '.tmp'
                    if file_exists(tmp_filename):
                        os.remove(tmp_filename)

                # untar/extract any detected archive file(s)
                if untar_archives is True:
                    if decrypted_filename.endswith('.tar') and tarfile.is_tarfile(decrypted_filename):
                        untar_path_tuple = os.path.split(decrypted_filename)
                        untar_path = untar_path_tuple[0]
                        if use_file_overwrite:
                            with tarfile.open(decrypted_filename) as tar:
                                if len(untar_path) > 0:
                                    tar.extractall(path=untar_path)  # use dir path from the decrypted_filename if not CWD
                                    stdout("'" + decrypted_filename + "' unpacked in the directory path '" + untar_path + "'")
                                else:
                                    tar.extractall()  # else use CWD
                                    stdout("'" + decrypted_filename + "' unpacked in the current working directory")
                        else:
                            with tarfile.TarFile(decrypted_filename, 'r', errorlevel=1) as tar:
                                for tarinfo in tar:
                                    t_file = tarinfo.name
                                    if len(untar_path) > 0:
                                        t_file_path = os.path.join(untar_path, t_file)
                                    else:
                                        t_file_path = t_file
                                    if not os.path.exists(t_file_path):
                                        try:
                                            if len(untar_path) > 0:
                                                tar.extract(t_file, path=untar_path)  # write to the appropriate dir
                                            else:
                                                tar.extract(t_file)  # write to CWD
                                        except IOError as e:
                                            stderr(
                                                "Failed to unpack the file '" + t_file_path + "' [" + str(
                                                    e) + "]")
                                    elif is_dir(t_file_path):
                                        pass  # do nothing if it exists and is a directory, no need to warn
                                    else:  # it is a file and it already exists, provide user error message
                                        stderr(
                                            "Failed to unpack the file '" + t_file_path + "'. File already exists. Use the --overwrite flag to replace existing files.")

                        # remove the decrypted tar archive file
                        os.remove(decrypted_filename)

            # overwrite the entered passphrases after file decryption is complete for all files
            passphrase = ""
            passphrase_confirm = ""

            # add a short pause to hinder brute force pexpect style password attacks with decrypto
            sleep(0.2)  # 200ms pause

        else:  # passphrases did not match
            passphrase = ""
            passphrase_confirm = ""
            stderr("The passphrases did not match.  Please enter your command again.")
            sys.exit(1)

    elif c.argc == 1:
        # simple single file or directory processing with default settings
        path = c.arg0
        if file_exists(path):  # SINGLE FILE
            check_existing_file = False  # check for a file with the name of new decrypted filename in the directory

            if path.endswith('.crypt'):
                decrypted_filename = path[0:-6]  # remove the .crypt suffix
                check_existing_file = True
            elif path.endswith('.gpg') or path.endswith('.pgp') or path.endswith('.asc'):
                decrypted_filename = path[0:-4]
                check_existing_file = True
            else:
                decrypted_filename = path + ".decrypt"  # if there is not a standard file type, then add a .decrypt suffix to the decrypted file name
                stdout("Could not confirm that the requested file is encrypted based upon the file type.  Attempting decryption.  Keep your fingers crossed...")

            # confirm that the decrypted path does not already exist, if so abort with warning message to user
            if check_existing_file is True:
                if file_exists(decrypted_filename):
                    stderr("Your file will be decrypted to '" + decrypted_filename + "' and this file path already exists.  Please move the file or use the --overwrite option with your command if you intend to replace the current file.")
                    sys.exit(1)

            # get passphrase used to symmetrically decrypt the file
            passphrase = getpass.getpass("Please enter your passphrase: ")
            if len(passphrase) == 0:  # confirm that user entered a passphrase
                stderr("You did not enter a passphrase. Please repeat your command and try again.")
                sys.exit(1)
            passphrase_confirm = getpass.getpass("Please enter your passphrase again: ")

            # confirm that the passphrases match
            if passphrase == passphrase_confirm:
                system_command = "gpg --batch -o " + quote(decrypted_filename) + " --passphrase " + quote(passphrase) + " -d " + quote(path)
                response = muterun(system_command)

                if response.exitcode == 0:
                    # unpack tar archive generated from the decryption, if present
                    if decrypted_filename.endswith('.tar') and tarfile.is_tarfile(decrypted_filename):
                        untar_path_tuple = os.path.split(decrypted_filename)
                        untar_path = untar_path_tuple[0]

                        with tarfile.TarFile(decrypted_filename, 'r', errorlevel=1) as tar:
                            for tarinfo in tar:
                                t_file = tarinfo.name
                                if len(untar_path) > 0:
                                    t_file_path = os.path.join(untar_path, t_file)
                                else:
                                    t_file_path = t_file
                                if not os.path.exists(t_file_path):
                                    try:
                                        if len(untar_path) > 0:
                                            tar.extract(t_file, path=untar_path)  # write to the appropriate dir
                                        else:
                                            tar.extract(t_file)  # write to CWD
                                    except IOError as e:
                                        stderr("Failed to unpack the file '" + t_file_path + "' [" + str(e) + "]")
                                elif is_dir(t_file_path):
                                    pass   # do nothing if it exists and is a directory, no need to warn
                                else:  # it is a file and it already exists, provide user error message
                                    stderr("Failed to unpack the file '" + t_file_path + "'. File already exists. Use the --overwrite flag to replace existing files.")

                        # remove the decrypted tar archive
                        os.remove(decrypted_filename)

                    stdout("Decryption complete")
                    # overwrite user entered passphrases
                    passphrase = ""
                    passphrase_confirm = ""
                    sys.exit(0)
                else:
                    stderr(response.stderr)
                    stderr("Decryption failed")
                    # overwrite user entered passphrases
                    passphrase = ""
                    passphrase_confirm = ""
                    # add a short pause to hinder brute force pexpect style password attacks with decrypto
                    sleep(0.2)  # 200ms pause
                    sys.exit(1)
            else:
                stderr("The passphrases did not match.  Please enter your command again.")
                sys.exit(1)
        elif dir_exists(path):  # SINGLE DIRECTORY
            dirty_directory_file_list = list_all_files(path)
            directory_file_list = [x for x in dirty_directory_file_list if (x.endswith('.crypt') or x.endswith('.gpg') or x.endswith('.pgp') or x.endswith('.asc'))]

            # if there are no encrypted files found, warn and abort
            if len(directory_file_list) == 0:
                stderr("There are no encrypted files in the directory")
                sys.exit(1)

            # prompt for the passphrase
            passphrase = getpass.getpass("Please enter your passphrase: ")
            if len(passphrase) == 0:  # confirm that user entered a passphrase
                stderr("You did not enter a passphrase. Please repeat your command and try again.")
                sys.exit(1)
            passphrase_confirm = getpass.getpass("Please enter your passphrase again: ")

            if passphrase == passphrase_confirm:
                # decrypt all of the encypted files in the directory
                for filepath in directory_file_list:
                    absolute_filepath = make_path(path, filepath)  # combine the directory path and file name into absolute path

                    # remove file suffix from the decrypted file path that writes to disk
                    if absolute_filepath.endswith('.crypt'):
                        decrypted_filepath = absolute_filepath[0:-6]  # remove the .crypt suffix
                    elif absolute_filepath.endswith('.gpg') or absolute_filepath.endswith('.pgp') or absolute_filepath.endswith('.asc'):
                        decrypted_filepath = absolute_filepath[0:-4]

                    # confirm that the file does not already exist
                    if file_exists(decrypted_filepath):
                        stdout("The file path '" + decrypted_filepath + "' already exists.  This file was not decrypted.")
                    else:
                        system_command = "gpg --batch -o " + quote(decrypted_filepath) + " --passphrase " + quote(passphrase) + " -d " + quote(absolute_filepath)
                        response = muterun(system_command)

                        if response.exitcode == 0:
                            stdout("'" + absolute_filepath + "' decrypted to '" + decrypted_filepath + "'")
                        else:
                            stderr(response.stderr)
                            stderr("Decryption failed for " + absolute_filepath)
                # overwrite user entered passphrases
                passphrase = ""
                passphrase_confirm = ""

                # add a short pause to hinder brute force pexpect style password attacks with decrypto
                sleep(0.2)  # 200ms pause
            else:
                # overwrite user entered passphrases
                passphrase = ""
                passphrase_confirm = ""
                stderr("The passphrases did not match.  Please enter your command again.")
                sys.exit(1)
        else:
            # error message, not a file or directory.  user entry error
            stderr("The path that you entered does not appear to be an existing file or directory.  Please try again.")
            sys.exit(1)

    # ------------------------------------------------------------------------------------------
    # [ DEFAULT MESSAGE FOR MATCH FAILURE ]
    #  Message to provide to the user when all above conditional logic fails to meet a true condition
    # ------------------------------------------------------------------------------------------
    else:
        print("Could not complete your request.  Please try again.")
        sys.exit(1)

if __name__ == '__main__':
    main()
