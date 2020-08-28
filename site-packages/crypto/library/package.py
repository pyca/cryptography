#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import tarfile
from Naked.toolshed.system import stderr, dir_exists, file_exists

# ------------------------------------------------------------------------------
# PUBLIC
# ------------------------------------------------------------------------------


def generate_tar_files(directory_list):
    """Public function that reads a list of local directories and generates tar archives from them"""
    
    tar_file_list = []

    for directory in directory_list:
        if dir_exists(directory):
            _generate_tar(directory)                  # create the tar archive
            tar_file_list.append(directory + '.tar')  # append the tar archive filename to the returned tar_file_list list
        else:
            stderr("The directory '" + directory + "' does not exist and a tar archive could not be created from it.", exit=1)            

    return tar_file_list


def remove_tar_files(file_list):
    """Public function that removes temporary tar archive files in a local directory"""
    for f in file_list:
        if file_exists(f) and f.endswith('.tar'):
            os.remove(f)  # remove any tar files in the list, if it does not appear to be a tar file, leave it alone

# ------------------------------------------------------------------------------
# PRIVATE
# ------------------------------------------------------------------------------


def _generate_tar(dir_path):
    """Private function that reads a local directory and generates a tar archive from it"""
    try:
        with tarfile.open(dir_path + '.tar', 'w') as tar:
            tar.add(dir_path)
    except tarfile.TarError as e:
        stderr("Error: tar archive creation failed [" + str(e) + "]", exit=1)
