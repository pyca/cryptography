#!/usr/bin/env python
# encoding: utf-8

#------------------------------------------------------------------------------
# The Ink Templating System
#  A lightweight, fast, flexible text templating system
#  Copyright 2014 Christopher Simpkins
#  MIT License
#------------------------------------------------------------------------------
import re

#------------------------------------------------------------------------------
# Template class
#  A template string class that is inherited from Python str
#  Includes metadata about the template:
#    odel = opening delimiter
#    cdel = closing delimiter
#    varlist = inclusive list of all variables in the template text (parsed in constructor)
#  Delimiters:
#    default = {{variable}}
#    assign new opening and closing delimiters as parameters when you make a new Template instance
#    `escape_regex` boolean is a speedup, avoids Python escape of special regex chars if you do not need it
#------------------------------------------------------------------------------
class Template(str):
    def __new__(cls, template_text, open_delimiter="{{", close_delimiter="}}", escape_regex=False):
        obj = str.__new__(cls, template_text)
        obj.odel = open_delimiter
        obj.cdel = close_delimiter
        obj.varlist = obj._make_var_list(template_text, escape_regex) #contains all unique parsed variables from the template in a list
        return obj

    #------------------------------------------------------------------------------
    # [ _make_var_list method ] (list of strings)
    #   Private method that parses the template string for all variables that match the delimiter pattern
    #   Returns a list of the variable names as strings
    #------------------------------------------------------------------------------
    def _make_var_list(self, template_text, escape_regex=False):
        if escape_regex:
            open_match_pat = self._escape_regex_special_chars(self.odel)
            close_match_pat = self._escape_regex_special_chars(self.cdel)
            match_pat = open_match_pat + r'(.*?)' + close_match_pat # capture group contains the variable name used between the opening and closing delimiters
        else:
            match_pat = self.odel + r'(.*?)' + self.cdel
        var_list = re.findall(match_pat, template_text) #generate a list that contains the capture group from the matches (i.e. the variables in the template)
        return set(var_list) # remove duplicate entries by converting to set (and lookup speed improvement from hashing)

    #------------------------------------------------------------------------------
    # [ _escape_regex_special_chars method ] (string)
    #   Private method that escapes special regex metacharacters
    #   Returns a string with the escaped character modifications
    #------------------------------------------------------------------------------
    def _escape_regex_special_chars(self, test_escape_string):
        return re.escape(test_escape_string)

#------------------------------------------------------------------------------
# Renderer class
#  Render the variable replacements in the ink template using a Python dictionary key argument
#  Construct the instace of the Renderer with the Ink template and the dictionary key
#  Run the renderer with the render method on the instance (e.g. r.render())
#  Parameters to constructor:
#    - template = an Ink Template instance
#    - key = a dictionary mapped key = variable name : value = variable replacement data
#    - html_entities = encode html entities with HTML escaped characters (default = False = do not encode)
#------------------------------------------------------------------------------

class Renderer:
    def __init__(self, template, key, html_entities=False):
        self.odel = template.odel
        self.cdel = template.cdel
        self.template = template
        self.html_entities = html_entities
        self.key_dict = key

    #------------------------------------------------------------------------------
    # [ render method ] (string)
    #   renders the variable replacements in the Ink template
    #   returns the rendered template as a string
    #------------------------------------------------------------------------------
    def render(self):
        # make local variables for the loop below (faster)
        local_dict = self.key_dict
        local_template = self.template
        local_varlist = self.template.varlist
        local_odel = self.odel
        local_cdel = self.cdel
        local_htmlent = self.html_entities
        if local_htmlent:
            from xml.sax.saxutils import escape #from Python std lib
        for key in local_dict:
            if key in local_varlist:
                value = local_dict[key]
                replace_string = local_odel + key + local_cdel
                if local_htmlent:
                    value = escape(value) #xml.sax.saxutils function
                local_template = local_template.replace(replace_string, value)
        return local_template

    ##TODO : multiple file render method?


if __name__ == '__main__':
    pass
    # template = Template("This is a of the {{test}} of the {{document}} {{type}} and more of the {{test}} {{document}} {{type}}")
    # renderer = Renderer(template, {'test': 'ব য', 'document':'testing document', 'type':'of mine', 'bogus': 'bogus test'})
    # print(renderer.render())
