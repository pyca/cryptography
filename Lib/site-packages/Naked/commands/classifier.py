#!/usr/bin/env python
# encoding: utf-8

from Naked.toolshed.system import exit_success

class Classifier:
    def __init__(self, search_string):
        self.needle = search_string
        self.url = 'https://pypi.python.org/pypi?%3Aaction=list_classifiers'

    def run(self):
        from Naked.toolshed.network import HTTP
        http = HTTP(self.url) # use the python.org url for the classifier list

        print('•naked• Pulling the classifier list from python.org...')

        res = http.get() # get the list
        test_list = res.split('\n') # split on newlines

        if self.needle == "": # user did not enter a search string, print the entire list
            print("•naked• You did not provide a search string.  Here is the entire list:")
            print(' ')
            for item in test_list:
                print(item)
        else: # user entered a search string, find it
            lower_needle = self.needle.lower()
            print("•naked• Performing a case insensitive search for '" + self.needle + "'")
            print(' ')
            filtered_list = [ x for x in test_list if lower_needle in x.lower() ] #case insensitive match for the search string
            for item in filtered_list:
                print(item)

        exit_success() # exit with zero status code

def help():
    help_string = """
Naked classify Command Help
===========================
The classify command performs a case-insensitive search of the PyPI application classifier list and displays the results.

USAGE
  naked classify [search string]

The search string argument is optional.  If you do not include a search string, the entire classifier list is displayed.

SECONDARY COMMANDS
  none

OPTIONS
  none

EXAMPLES
  naked classify
  naked classify Internet
"""
    print(help_string)
    exit_success()

if __name__ == '__main__':
    pass
