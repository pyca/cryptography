# -*- coding: utf8 -*-

"""
clint.textui.prompt
~~~~~~~~~~~~~~~~~~~

Module for simple interactive prompts handling

"""

from __future__ import absolute_import, print_function

from re import match, I

from .core import puts
from .colored import yellow
from .validators import RegexValidator, OptionValidator

try:
    raw_input
except NameError:
    raw_input = input


def yn(prompt, default='y', batch=False):
    # A sanity check against default value
    # If not y/n then y is assumed
    if default not in ['y', 'n']:
        default = 'y'

    # Let's build the prompt
    choicebox = '[Y/n]' if default == 'y' else '[y/N]'
    prompt = prompt + ' ' + choicebox + ' '

    # If input is not a yes/no variant or empty
    # keep asking
    while True:
        # If batch option is True then auto reply
        # with default input
        if not batch:
            input = raw_input(prompt).strip()
        else:
            print(prompt)
            input = ''

        # If input is empty default choice is assumed
        # so we return True
        if input == '':
            return True

        # Given 'yes' as input if default choice is y
        # then return True, False otherwise
        if match('y(?:es)?', input, I):
            return True if default == 'y' else False

        # Given 'no' as input if default choice is n
        # then return True, False otherwise
        elif match('n(?:o)?', input, I):
            return True if default == 'n' else False


def query(prompt, default='', validators=None, batch=False):
    # Set the nonempty validator as default
    if validators is None:
        validators = [RegexValidator(r'.+')]

    # Let's build the prompt
    if prompt[-1] is not ' ':
        prompt += ' '

    if default:
        prompt += '[' + default + '] '

    # If input is not valid keep asking
    while True:
        # If batch option is True then auto reply
        # with default input
        if not batch:
            user_input = raw_input(prompt).strip() or default
        else:
            print(prompt)
            user_input = ''

        # Validate the user input
        try:
            for validator in validators:
                user_input = validator(user_input)
            return user_input
        except Exception as e:
            puts(yellow(e.message))



def options(prompt, options, default=None, batch=False):
    '''

    :param prompt:
    :param options:
        this can be either a list of strings, in which case it will be presented like:
        prompt:
            (1) this is the first string
            (2) this is the second string
            (3) this is the third string

            please select 1-3:

        or a list of dictionaries in the format of:
            { { 'selector' : 'this is what the user will enter to select the option'
                'prompt': 'this is the string that will be displayed, this can be omitted if the selector is also a prompt',
                'return': 'this is what is returned to the calling procedure, if omitted, the option selector will be used' }

        so, to replicate the above, the dict could look like:

        [ {'selector':1,'prompt':'this is the first string','return':1},
          {'selector':2,'prompt':'this is the second string','return':2},
          {'selector':3,'prompt':'this is the third string'}

    :param default: should be set to the default selector (if desired)
    :param batch: True/False, will auto-return the default
    :return:
    '''
    # Build fix options and build validator

    validator_list = []
    return_dict = {}

    if isinstance(options[0],dict):
        for item in options:
            item['selector'] = str(item['selector'])
            item['prompt'] = str(item['prompt'])
            if 'return' not in item:
                item['return'] = item['selector']
            validator_list.append(item['selector'])
            return_dict[item['selector']] = item['return']
    else:
        options_strings = options
        options = []
        for key, opt in enumerate(options_strings):
            item = {}
            item['selector'] = str(key+1)
            item['prompt'] = str(opt)
            item['return'] = key+1

            return_dict[item['selector']] = item['return']
            validator_list.append(item['selector'])
            options.append(item)

    validators = [OptionValidator(validator_list)]

    # Let's build the prompt

    prompt += '\n'

    # building the options list
    for o in options:
        prompt += '[{selector}] {prompt}\n'.format(**o)

    prompt += '\n'

    if default:
        prompt += '[' + default + '] '

    # If input is not valid keep asking
    while True:
        # If batch option is True then auto reply
        # with default input
        if not batch:
            user_input = raw_input(prompt).strip() or default
        else:
            print(prompt)
            user_input = ''


        # Validate the user input
        try:
            for validator in validators:
                user_input = validator(user_input)
                # convert user input to defined return value
                user_input = return_dict[user_input]
            return user_input
        except Exception as e:
            puts(yellow(e.message))
