#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from Naked.toolshed.shell import muterun
from Naked.toolshed.system import file_size, stdout, stderr

from shellescape import quote

# ------------------------------------------------------------------------------
# Cryptor class
#   performs gpg encryption of one or more files
# ------------------------------------------------------------------------------


class Cryptor(object):
    """performs gpg encryption of one or more files"""
    def __init__(self, passphrase):
        self.command_default = "gpg -z 1 --batch --force-mdc --cipher-algo AES256 -o "
        self.command_nocompress = "gpg -z 0 --batch --force-mdc --cipher-algo AES256 -o "
        self.command_maxcompress = "gpg -z 7 --batch --force-mdc --cipher-algo AES256 -o "
        self.command_default_armored = "gpg -z 1 --armor --batch --force-mdc --cipher-algo AES256 -o "
        self.command_nocompress_armored = "gpg -z 0 --armor --batch --force-mdc --cipher-algo AES256 -o "
        self.command_maxcompress_armored = "gpg -z 7 --armor --batch --force-mdc --cipher-algo AES256 -o "
        self.passphrase = passphrase
        self.common_binaries = set(['.7z', '.gz', '.aac', '.app', '.avi', '.azw', '.bz2', '.deb', '.doc', '.dmg', '.exe', '.flv', '.gif', '.jar', '.jpg', '.mov', '.mp3', '.mp4', '.odt', '.oga', '.ogg', '.ogm', '.pdf', '.pkg', '.png', '.ppt', '.pps', '.psd', '.rar', '.rpm', '.tar', '.tif', '.wav', '.wma', '.wmv', '.xls', '.zip', '.aiff', '.docx', '.epub', '.flac', '.mpeg', '.jpeg', '.pptx', '.xlsx'])
        self.common_text = set(['.c', '.h', '.m', '.cc', '.js', '.pl', '.py', '.rb', '.sh', '.cpp', '.css', '.csv', '.php', '.rss', '.txt', '.xml', '.yml', '.java', '.json', '.html', '.yaml'])

    # ------------------------------------------------------------------------------
    # PUBLIC methods
    # ------------------------------------------------------------------------------

    # ------------------------------------------------------------------------------
    # encrypt_file : file encryption method
    # ------------------------------------------------------------------------------
    def encrypt_file(self, inpath, force_nocompress=False, force_compress=False, armored=False, checksum=False):
        """public method for single file encryption with optional compression, ASCII armored formatting, and file hash digest generation"""
        if armored:
            if force_compress:
                command_stub = self.command_maxcompress_armored
            elif force_nocompress:
                command_stub = self.command_nocompress_armored
            else:
                if self._is_compress_filetype(inpath):
                    command_stub = self.command_default_armored
                else:
                    command_stub = self.command_nocompress_armored
        else:
            if force_compress:
                command_stub = self.command_maxcompress
            elif force_nocompress:
                command_stub = self.command_nocompress
            else:
                if self._is_compress_filetype(inpath):
                    command_stub = self.command_default
                else:
                    command_stub = self.command_nocompress

        encrypted_outpath = self._create_outfilepath(inpath)
        system_command = command_stub + encrypted_outpath + " --passphrase " + quote(self.passphrase) + " --symmetric " + quote(inpath)

        try:
            response = muterun(system_command)
            # check returned status code
            if response.exitcode == 0:
                stdout(encrypted_outpath + " was generated from " + inpath)
                if checksum:  # add a SHA256 hash digest of the encrypted file - requested by user --hash flag in command
                    from crypto.library import hash
                    encrypted_file_hash = hash.generate_hash(encrypted_outpath)
                    if len(encrypted_file_hash) == 64:
                        stdout("SHA256 hash digest for " + encrypted_outpath + " :")
                        stdout(encrypted_file_hash)
                    else:
                        stdout("Unable to generate a SHA256 hash digest for the file " + encrypted_outpath)
            else:
                stderr(response.stderr, 0)
                stderr("Encryption failed")
                sys.exit(1)
        except Exception as e:
            stderr("There was a problem with the execution of gpg. Encryption failed. Error: [" + str(e) + "]")
            sys.exit(1)

    # ------------------------------------------------------------------------------
    # encrypt_files : multiple file encryption
    # ------------------------------------------------------------------------------
    def encrypt_files(self, file_list, force_nocompress=False, force_compress=False, armored=False, checksum=False):
        """public method for multiple file encryption with optional compression, ASCII armored formatting, and file hash digest generation"""
        for the_file in file_list:
            self.encrypt_file(the_file, force_nocompress, force_compress, armored, checksum)

    # ------------------------------------------------------------------------------
    # cleanup : overwrite the passphrase in memory
    # ------------------------------------------------------------------------------
    def cleanup(self):
        """public method that overwrites user passphrase in memory"""
        self.passphrase = ""

    # ------------------------------------------------------------------------------
    # PRIVATE methods
    # ------------------------------------------------------------------------------

    def _create_outfilepath(self, inpath):
        """private method that generates the crypto saved file path string with a .crypt file type"""
        return inpath + '.crypt'

    def _is_compress_filetype(self, inpath):
        """private method that performs magic number and size check on file to determine whether to compress the file"""
        # check for common file type suffixes in order to avoid the need for file reads to check magic number for binary vs. text file
        if self._is_common_binary(inpath):
            return False
        elif self._is_common_text(inpath):
            return True
        else:
            # files > 10kB get checked for compression (arbitrary decision to skip compression on small files)
            the_file_size = file_size(inpath)
            if the_file_size > 10240:
                if the_file_size > 512000:  # seems to be a break point at ~ 500kb where file compression offset by additional file read, so limit tests to files > 500kB
                    try:
                        system_command = "file --mime-type -b " + quote(inpath)
                        response = muterun(system_command)
                        if response.stdout[0:5] == "text/":  # check for a text file mime type
                            return True   # appropriate size, appropriate file mime type
                        else:
                            return False  # appropriate size, inappropriate file mime type
                    except Exception:
                        return False
                else:
                    return True  # if file size is < 500kB, skip the additional file read and just go with compression
            else:
                return False  # below minimum size to consider compression, do not compress

    def _is_common_binary(self, inpath):
        """private method to compare file path mime type to common binary file types"""
        # make local variables for the available char numbers in the suffix types to be tested
        two_suffix = inpath[-3:]
        three_suffix = inpath[-4:]
        four_suffix = inpath[-5:]
        
        # test for inclusion in the instance variable common_binaries (defined in __init__)
        if two_suffix in self.common_binaries:
            return True
        elif three_suffix in self.common_binaries:
            return True
        elif four_suffix in self.common_binaries:
            return True
        else:
            return False

    def _is_common_text(self, inpath):
        """private method to compare file path mime type to common text file types"""
        # make local variables for the available char numbers in the suffix types to be tested
        one_suffix = inpath[-2:]
        two_suffix = inpath[-3:]
        three_suffix = inpath[-4:]
        four_suffix = inpath[-5:]
        
        # test for inclusion in the instance variable common_text (defined in __init__)
        if one_suffix in self.common_text:
            return True
        elif two_suffix in self.common_text:
            return True
        elif three_suffix in self.common_text:
            return True
        elif four_suffix in self.common_text:
            return True
        else:
            return False
