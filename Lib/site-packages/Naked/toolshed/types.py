#!/usr/bin/env python
# encoding: utf-8

import sys
from Naked.settings import debug as DEBUG_FLAG

#------------------------------------------------------------------------------
# [[ NakedObject class ]]
#   A generic Python object
#   Assigns object attributes by key name in the dictionary argument to the constructor
#   The methods are inherited by other mutable Naked object extension types
#   Attribute accessors: hasattr, getattr, setattr, delattr
#------------------------------------------------------------------------------
class NakedObject(object):
    # initialize with an attributes dictionary {attribute_name: attribute_value}
    def __init__(self, attributes={}, naked_type='NakedObject'):
        if len(attributes) > 0:
            for key in attributes:
                setattr(self, key, attributes[key])
        setattr(self, '_naked_type_', naked_type) # maintain an attribute to keep track of the extension type

    #------------------------------------------------------------------------------
    # [ _getAttributeDict method ] (dictionary)
    #  returns a dictionary of the NakedObject instance attributes
    #------------------------------------------------------------------------------
    def _getAttributeDict(self):
        return self.__dict__

    #------------------------------------------------------------------------------
    # [ _equal_type method ] (boolean)
    #  returns boolean for type of instance == type of test parameter instance
    #------------------------------------------------------------------------------
    def _equal_type(self, other_obj):
        return type(self) == type(other_obj)

    #------------------------------------------------------------------------------
    # [ _equal_attributes metod ] (method)
    #  returns boolean for instance.__dict__ == test parameter .__dict__ (attribute comparison)
    #------------------------------------------------------------------------------
    def _equal_attributes(self, other_obj):
        return self.__dict__ == other_obj.__dict__

    #------------------------------------------------------------------------------
    # == overload
    #------------------------------------------------------------------------------
    def __eq__(self, other_obj):
        return self.equals(other_obj)

    #------------------------------------------------------------------------------
    # != overload
    #------------------------------------------------------------------------------
    def __ne__(self, other_obj):
        result = self.equals(other_obj)
        if result:
            return False # reverse result of the equals method
        else:
            return True

    #------------------------------------------------------------------------------
    # [ equals method ] (boolean)
    #   equality testing based on type and attributes
    #   **NEED TO OVERRIDE IN CLASSES THAT INHERIT
    #------------------------------------------------------------------------------
    def equals(self, other_obj):
        return self._equal_type(other_obj) and self._equal_attributes(other_obj)

    #------------------------------------------------------------------------------
    # [ type method ] (string)
    #  returns the Naked type extension string that is set in the constructor for each object type
    #------------------------------------------------------------------------------
    def type(self):
        if hasattr(self, '_naked_type_'):
            return self._naked_type_
        else:
            return None

#------------------------------------------------------------------------------
# [[ XDict class ]]
#   An inherited extension to the dictionary type
#------------------------------------------------------------------------------
class XDict(dict, NakedObject):
    def __init__(self, dict_obj, attributes={}, naked_type='XDict'):
        dict.__init__(self, dict_obj)
        NakedObject.__init__(self, attributes, naked_type)

    #------------------------------------------------------------------------------
    # XDict Operator Overloads
    #------------------------------------------------------------------------------

    #------------------------------------------------------------------------------
    # + overload
    #   overwrites existing keys with key:value pairs from new dictionaries if they are the same keys
    #   returns the updated XDict object
    #------------------------------------------------------------------------------
    def __add__(self, other_dict):
        try:
            self.update(other_dict)
            if hasattr(other_dict, '_naked_type_') and (getattr(other_dict, '_naked_type_') == 'XDict'):
                attr_dict = other_dict._getAttributeDict() # get the attributes from the parameter XDict and add to new XDict
                if len(attr_dict) > 0:
                    for key in attr_dict:
                        setattr(self, key, attr_dict[key])
            return self
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: unable to combine XDict with parameter provided (Naked.toolshed.types.py)")
            raise e

    #------------------------------------------------------------------------------
    #  +- overload
    #  overwrites existing keys with another_dict (right sided argument) keys if they are the same keys
    #  returns the updated XDict object
    #------------------------------------------------------------------------------
    def __iadd__(self, other_dict):
        try:
            self.update(other_dict)
            if hasattr(other_dict, '_naked_type_') and (getattr(other_dict, '_naked_type_') == 'XDict'):
                attr_dict = other_dict._getAttributeDict() # get the attributes from the parameter XDict and add to new XDict
                if len(attr_dict) > 0:
                    for key in attr_dict:
                        setattr(self, key, attr_dict[key])
            return self
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: unable to combine XDict with parameter provided (Naked.toolshed.types.py)")
            raise e

    #------------------------------------------------------------------------------
    # == overload
    #------------------------------------------------------------------------------
    def __eq__(self, other_obj):
        return self.equals(other_obj)

    #------------------------------------------------------------------------------
    # != overload
    #------------------------------------------------------------------------------
    def __ne__(self, other_obj):
        result = self.equals(other_obj)
        if result:
            return False # reverse result of the equals method
        else:
            return True

    #------------------------------------------------------------------------------
    # [ equals method ] (boolean)
    #   tests for equality of the XDict (type, attributes, dictionary equality)
    #------------------------------------------------------------------------------
    def equals(self, other_obj):
        if self._equal_type(other_obj) and self._equal_attributes(other_obj):
            if dict(self) == dict(other_obj):
                return True
            else:
                return False
        else:
            return False

    #------------------------------------------------------------------------------
    # XDict Value Methods
    #------------------------------------------------------------------------------
    #------------------------------------------------------------------------------
    # [ conditional_map_to_vals method ] (XDict)
    #  returns the original XDict with values that meet True condition in `conditional_function`
    #  modified as per the `mapped_function` with single value argument call
    #  Test: test_xdict_conditional_map
    #------------------------------------------------------------------------------
    def conditional_map_to_vals(self, conditional_function, mapped_function):
        for key, value in self.xitems():
            if conditional_function(key):
                self[key] = mapped_function(value)
        return self

    #------------------------------------------------------------------------------
    # [ map_to_vals method ] (XDict)
    #  returns the original XDict with all values modified as per the `mapped_function`
    #  Test: test_xdict_map_to_vals
    #------------------------------------------------------------------------------
    def map_to_vals(self, mapped_function):
        # return XDict( zip(self, map(mapped_function, self.values())), self._getAttributeDict() ) - slower in Py2
        for key, value in self.xitems():
            self[key] = mapped_function(value)
        return self

    #------------------------------------------------------------------------------
    # [ val_xlist method ] (XList)
    #  return an XList of the values in the XDict
    #  Test: test_xdict_val_xlist
    #------------------------------------------------------------------------------
    def val_xlist(self):
        return XList(self.values(), self._getAttributeDict())

    #------------------------------------------------------------------------------
    # [ max_val method ] (tuple of maximum value and associated key)
    #  Test: test_xdict_max_val, test_xdict_max_val_strings (strings are alphabetic if not numerals)
    #------------------------------------------------------------------------------
    def max_val(self):
        return max(zip(self.values(), self.keys()))

    #------------------------------------------------------------------------------
    # [ min_val method ] (tuple of minimum value and associated key)
    #------------------------------------------------------------------------------
    def min_val(self):
        return min(zip(self.values(), self.keys()))

    #------------------------------------------------------------------------------
    # [ sum_vals method ] (numeric return type dependent upon original value type)
    #  returns sum of all values in the dictionary
    #------------------------------------------------------------------------------
    def sum_vals(self):
        return sum(self.values())

    #------------------------------------------------------------------------------
    # [ val_count method ] (integer)
    #  returns an integer value for the total count of `value_name` in the dictionary values
    #  Case sensitive test if comparing strings
    #  Tests: test_xdict_val_count_string, test_xdict_val_count_integer
    #------------------------------------------------------------------------------
    def val_count(self, value_name):
        count = 0
        for test_value in self.values():
            if value_name == test_value:
                count += 1
        return count

    #------------------------------------------------------------------------------
    # [ value_count_ci method ] (integer)
    #  returns an integer value for the total count of case insensitive `value_name`
    #  strings/char in the dictionary values.  Can include non-string types (ignores them)
    #  Test: test_xdict_val_count_ci
    #------------------------------------------------------------------------------
    def val_count_ci(self, value_name):
        count = 0
        for test_value in self.values():
            try:
                if value_name.lower() in test_value.lower():
                    count += 1
            except AttributeError: # the test_value was not a string, catch exception and continue count attempt
                continue
        return count


    #------------------------------------------------------------------------------
    # XDict Key Methods
    #------------------------------------------------------------------------------
    #------------------------------------------------------------------------------
    # [ difference method ] (difference set of keys)
    #  definition: keys that are included in self, but not in `another_dict`
    #  Tests: test_xdict_key_difference, test_xdict_key_difference_when_none_present
    #------------------------------------------------------------------------------
    def difference(self, another_dict):
        return set(self.keys()) - set(another_dict.keys())

    #------------------------------------------------------------------------------
    # [ intersection method ] (intersection set of keys)
    #   definition: keys that are included in both self and `another_dict`
    #   Tests: test_xdict_key_intersection, test_xdict_key_intersection_when_none_present
    #------------------------------------------------------------------------------
    def intersection(self, another_dict):
        return set(self.keys()) & set(another_dict.keys())

    #------------------------------------------------------------------------------
    # [ key_xlist method ] (XList)
    #  returns an XList of the keys in the XDict
    #  Test: test_xdict_key_xlist
    #------------------------------------------------------------------------------
    def key_xlist(self):
        return XList(self.keys(), self._getAttributeDict())

    #------------------------------------------------------------------------------
    # [ random method ] (dictionary)
    #  return new Python dictionary with single, random key:value pair
    #  Test: test_xdict_key_random
    #------------------------------------------------------------------------------
    def random(self):
        import random
        from Naked.toolshed.python import py_major_version
        random_key_list = random.sample(self.keys(), 1)
        the_key = random_key_list[0]
        return {the_key: self[the_key]}

    #------------------------------------------------------------------------------
    # [ random_sample method ] (dictionary)
    #  return new Python dictionary with `number_of_items` random key:value pairs
    #  Test: test_xdict_key_random_sample
    #------------------------------------------------------------------------------
    def random_sample(self, number_of_items):
        import random
        random_key_list = random.sample(self.keys(), number_of_items)
        new_dict = {}
        for item in random_key_list:
            new_dict[item] = self[item]
        return new_dict

    #------------------------------------------------------------------------------
    # [ xitems method ] (tuple)
    #   Generator method that returns tuples of every key, value in dictionary
    #   uses appropriate method from Python 2 and 3 interpreters
    #   Test: test_xdict_xitems
    #------------------------------------------------------------------------------
    def xitems(self):
        from Naked.toolshed.python import py_major_version
        if py_major_version() > 2:
            return self.items()
        else:
            return self.iteritems()

#------------------------------------------------------------------------------
# [[ XList class ]]
#  An inherited extension to the list object that permits attachment of attributes
#------------------------------------------------------------------------------
class XList(list, NakedObject):
    def __init__(self, list_obj, attributes={}, naked_type='XList'):
        list.__init__(self, list_obj)
        NakedObject.__init__(self, attributes, naked_type)

    #------------------------------------------------------------------------------
    # XList Operator Overloads
    #------------------------------------------------------------------------------

    #------------------------------------------------------------------------------
    # + operator overload
    #   extends XList with one or more other lists (`*other_lists`)
    #------------------------------------------------------------------------------
    def __add__(self, *other_lists):
        try:
            for the_list in other_lists:
                # add attributes if it is an XList
                if hasattr(the_list, '_naked_type_') and (getattr(the_list, '_naked_type_') == 'XList'):
                    attr_dict = the_list._getAttributeDict() # get XList attribute dictionary
                    if len(attr_dict) > 0:
                        for key in attr_dict:
                            setattr(self, key, attr_dict[key])
                # extend the XList items
                self.extend(the_list)
            return self
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: unable to combine XList with parameter provided (Naked.toolshed.types.py)")
            raise e

    #------------------------------------------------------------------------------
    # += overload
    #  extends XList with one other list (`another_list`)
    #------------------------------------------------------------------------------
    def __iadd__(self, another_list):
        try:
            #add attributes if it is an XList
            if hasattr(another_list, '_naked_type_') and (getattr(another_list, '_naked_type_') == 'XList'):
                    attr_dict = another_list._getAttributeDict() # get XList attribute dictionary
                    if len(attr_dict) > 0:
                        for key in attr_dict:
                            setattr(self, key, attr_dict[key])
            # extend the XList items
            self.extend(another_list)
            return self
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: unable to combine XList with parameter provided (Naked.toolshed.types.py)")
            raise e

    #------------------------------------------------------------------------------
    # == overload
    #------------------------------------------------------------------------------
    def __eq__(self, other_obj):
        return self.equals(other_obj)

    #------------------------------------------------------------------------------
    # != overload
    #------------------------------------------------------------------------------
    def __ne__(self, other_obj):
        result = self.equals(other_obj)
        if result:
            return False # reverse result of the equals method
        else:
            return True

    #------------------------------------------------------------------------------
    # [ equals method ] (boolean)
    #   tests for equality of the XList (type, attributes, list equality)
    #------------------------------------------------------------------------------
    def equals(self, other_obj):
        if self._equal_type(other_obj) and self._equal_attributes(other_obj):
            if list(self) == list(other_obj):
                return True
            else:
                return False
        else:
            return False

    #------------------------------------------------------------------------------
    # XList Methods
    #------------------------------------------------------------------------------

    #------------------------------------------------------------------------------
    # XList String Methods
    #------------------------------------------------------------------------------
    # [ join method ] (string)
    #  Concatenate strings in the list and return
    #  Default separator between string list values is an empty string
    #  Pass separator character(s) as an argument to the method
    #------------------------------------------------------------------------------
    def join(self, separator=""):
        return separator.join(self)

    #------------------------------------------------------------------------------
    # [ postfix method ] (list of strings)
    #  Append a string to each list item string
    #------------------------------------------------------------------------------
    def postfix(self, after):
        return [ "".join([x, after]) for x in self ]

    #------------------------------------------------------------------------------
    # [ prefix method ] (list of strings)
    #  Prepend a string to each list item string
    #------------------------------------------------------------------------------
    def prefix(self, before):
        return [ "".join([before, x]) for x in self ]

    #------------------------------------------------------------------------------
    # [ surround method ] (list of strings)
    #  Surround each list item string with a before and after string argument passed to the method
    #------------------------------------------------------------------------------
    def surround(self, before, after=""):
        if after == "":
            after = before
        return [ "".join([before, x, after]) for x in self ]

    #------------------------------------------------------------------------------
    # XList Numeric Methods
    #------------------------------------------------------------------------------
    # [ max method ] (list dependent type, single value)
    #  return maximum value from the list items
    #------------------------------------------------------------------------------
    def max(self):
        return max(self)

    #------------------------------------------------------------------------------
    # [ min method ] (list dependent type, single value)
    #  return minimum value from the list items
    #------------------------------------------------------------------------------
    def min(self):
        return min(self)

    #------------------------------------------------------------------------------
    # [ sum method ] (list dependent type, single value)
    #  return the sum of all list items
    #------------------------------------------------------------------------------
    def sum(self):
        return sum(self)

    #------------------------------------------------------------------------------
    # XList Data Management Methods
    #------------------------------------------------------------------------------
    #------------------------------------------------------------------------------
    # [ count_duplicates method ] (integer)
    #   returns an integer count of number of duplicate values
    #------------------------------------------------------------------------------
    def count_duplicates(self):
        return len(self) - len(set(self))

    #------------------------------------------------------------------------------
    # [ remove_duplicates ] (XList)
    #  returns a new XList with duplicates removed
    #------------------------------------------------------------------------------
    def remove_duplicates(self):
        return XList( set(self), self._getAttributeDict() )

    #------------------------------------------------------------------------------
    # [ difference method ] (set)
    #  returns a set containing items in XList that are not contained in `another_list`
    #------------------------------------------------------------------------------
    def difference(self, another_list):
        return set(self) - set(another_list)

    #------------------------------------------------------------------------------
    # [ intersection method ] (set)
    #  returns a set containing items that are in both XList and `another_list`
    #------------------------------------------------------------------------------
    def intersection(self, another_list):
        return set(self) & set(another_list)

    #------------------------------------------------------------------------------
    # XList Function Mapping Methods
    #------------------------------------------------------------------------------
    #------------------------------------------------------------------------------
    # [ map_to_items method ] (XList)
    #  returns original XList with modification of each item based upon `mapped_function`
    #------------------------------------------------------------------------------
    def map_to_items(self, mapped_function):
        # return XList( map(mapped_function, self), self._getAttributeDict() ) - slower
        for index, item in enumerate(self):
            self[index] = mapped_function(item)
        return self

    #------------------------------------------------------------------------------
    # [ conditional_map_to_items method ] (XList)
    #  returns original XList with modification of items that meet True condition in
    #  `conditional_function` with change performed as defined in `mapped_function`
    #------------------------------------------------------------------------------
    def conditional_map_to_items(self, conditional_function, mapped_function):
        for index, item in enumerate(self):
            if conditional_function(item):
                self[index] = mapped_function(item)
        return self

    #------------------------------------------------------------------------------
    # XList Descriptive Stats Methods
    #------------------------------------------------------------------------------
    #------------------------------------------------------------------------------
    # [ count_ci method ] (integer)
    #  returns an integer count of the number of case-insensitive items that match `test_string`
    #------------------------------------------------------------------------------
    def count_ci(self, test_string):
        count = 0
        for item in self:
            try:
                if test_string.lower() in item.lower():
                    count += 1
            except AttributeError: # the test_value was not a string, catch exception and continue count attempt
                continue
        return count

    #------------------------------------------------------------------------------
    # [ random method ] (list)
    #  returns a single item list with a random element from the original XList
    #------------------------------------------------------------------------------
    def random(self):
        import random
        return random.choice(self)

    #------------------------------------------------------------------------------
    # [ random_sample method ] (list)
    #  returns a list with one or more random items from the original XList
    #  number of items determined by the `number_of_items` argument
    #------------------------------------------------------------------------------
    def random_sample(self, number_of_items):
        import random
        return random.sample(self, number_of_items)

    #------------------------------------------------------------------------------
    # [ shuffle method ] (XList)
    #   randomly shuffle the contents of the list
    #------------------------------------------------------------------------------
    def shuffle(self):
        import random
        random.shuffle(self)
        return self

    #------------------------------------------------------------------------------
    # XList Match Methods
    #------------------------------------------------------------------------------
    #------------------------------------------------------------------------------
    # [ wildcard_match method ] (list)
    #  returns a list of items that match the `wildcard` argument
    #------------------------------------------------------------------------------
    def wildcard_match(self, wildcard):
        if hasattr(self, 'nkd_fnmatchcase'):
            fnmatchcase = self.nkd_fnmatchcase
        else:
            from fnmatch import fnmatchcase
            self.nkd_fnmatchcase = fnmatchcase
        return [ x for x in self if fnmatchcase(x, wildcard) ]

    #------------------------------------------------------------------------------
    # [ multi_wildcard_match method ] (list)
    #  returns a list of items that match one or more | separated wildcards passed as string
    #------------------------------------------------------------------------------
    def multi_wildcard_match(self, wildcards):
        if hasattr(self, 'nkd_fnmatchcase'):
            fnmatchcase = self.nkd_fnmatchcase
        else:
            from fnmatch import fnmatchcase
            self.nkd_fnmatchcase = fnmatchcase
        wc_list = wildcards.split('|')
        return_list = []
        for wc in wc_list:
            temp_list = [ x for x in self if fnmatchcase(x, wc) ]
            for result in temp_list:
                return_list.append(result)
        return return_list

    #------------------------------------------------------------------------------
    # XList Cast Methods
    #------------------------------------------------------------------------------
    #------------------------------------------------------------------------------
    # [ xset method ] (XSet)
    #  return an XSet with unique XList item values and XList attributes
    #------------------------------------------------------------------------------
    def xset(self):
        attr_dict = self._getAttributeDict()
        return XSet(set(self), attr_dict)

    #------------------------------------------------------------------------------
    # [ xfset method ] (XFSet)
    #  return an XFSet with unique XList item values and XList attributes
    #------------------------------------------------------------------------------
    def xfset(self):
        attr_dict = self._getAttributeDict()
        return XFSet(set(self), attr_dict)

    #------------------------------------------------------------------------------
    # [ xtuple method ] (XTuple)
    #  returns an XTuple with XList item values and XList attributes
    #------------------------------------------------------------------------------
    def xtuple(self):
        attr_dict = self._getAttributeDict()
        return XTuple(tuple(self), attr_dict)

#------------------------------------------------------------------------------
# [[ XMaxHeap class ]]
#    max heap queue
#------------------------------------------------------------------------------
from heapq import heappush, heappop
class XMaxHeap(NakedObject):
    def __init__(self, attributes={}, naked_type='XMaxHeap'):
        NakedObject.__init__(self, attributes, naked_type)
        self._queue = []
        self._index = 0

    # length of the queue
    def __len__(self):
        return len(self._queue)

    # O(log n) complexity
    def push(self, the_object, priority):
        heappush(self._queue, (-priority, self._index, the_object))
        self._index += 1

    # O(log n) complexity
    def pop(self):
        if self._queue:
            return heappop(self._queue)[-1]
        else:
            return None

    # push new object and return the highest priority object
    def pushpop(self, the_object, priority):
        heappush(self._queue, (-priority, self._index, the_object))
        self._index += 1
        if self._queue:
            return heappop(self._queue)[-1]
        else:
            return None # return None if the queue is empty

    # the length of the queue
    def length(self):
        return len(self._queue)

#------------------------------------------------------------------------------
# [[ XMinHeap class ]]
#    min heap queue
#------------------------------------------------------------------------------
from heapq import heappush, heappop
class XMinHeap(NakedObject):
    def __init__(self, attributes={}, naked_type='XMinHeap'):
        NakedObject.__init__(self, attributes, naked_type)
        self._queue = []
        self._index = 0


    # length of the queue
    def __len__(self):
        return len(self._queue)

    # O(log n) complexity
    def push(self, the_object, priority):
        heappush(self._queue, (priority, self._index, the_object))
        self._index += 1

    # O(log n) complexity
    def pop(self):
        if self._queue:
            return heappop(self._queue)[-1]
        else:
            return None # return None if the queue is empty

    # push new object and return the lowest priority object
    def pushpop(self, the_object, priority):
        heappush(self._queue, (priority, self._index, the_object))
        self._index += 1
        if self._queue:
            return heappop(self._queue)[-1]
        else:
            return None  #return None if the queue is empty

    # the length of the queue
    def length(self):
        return len(self._queue)

#------------------------------------------------------------------------------
# [[ XQueue class ]]
#
#------------------------------------------------------------------------------
from collections import deque
class XQueue(deque, NakedObject):
    def __init__(self, initial_iterable=[], attributes={}, max_length=10, naked_type='XQueue'):
        deque.__init__(self, initial_iterable, max_length)
        NakedObject.__init__(self, attributes, naked_type)


#------------------------------------------------------------------------------
# [[ XSet class ]]
#  An inherited extension to the mutable set object that permits attribute assignment
#  Inherits from set and from NakedObject (see methods in NakedObject at top of this module
#------------------------------------------------------------------------------
class XSet(set, NakedObject):
    def __init__(self, set_obj, attributes={}, naked_type='XSet'):
        set.__init__(self, set_obj)
        NakedObject.__init__(self, attributes, naked_type)

    #   += operator overload to extend the XSet with a second set
    def __iadd__(self, another_set):
        self.update(another_set)
        return self

    def xlist(self):
        attr_dict = self._getAttributeDict()
        return XList(list(self), attr_dict)

    def xfset(self):
        attr_dict = self._getAttributeDict()
        return XFSet(self, attr_dict)

#------------------------------------------------------------------------------
# [[ XFSet class ]]
#  An inherited extension to the immutable frozenset object that permits attribute assignment
#  Immutable so there is no setter method, attributes must be set in the constructor
#------------------------------------------------------------------------------
class XFSet(frozenset):
    def __new__(cls, the_set, attributes={}, naked_type="XFSet"):
        set_obj = frozenset.__new__(cls, the_set)
        if len(attributes) > 0:
            for key in attributes:
                setattr(set_obj, key, attributes[key])
        setattr(set_obj, '_naked_type_', naked_type) # set the naked extension type as an attribute (NakedObject does this for mutable classes)
        return set_obj

    def _getAttributeDict(self):
        return self.__dict__

    def xlist(self):
        attr_dict = self._getAttributeDict()
        return XList(list(self), attr_dict, naked_type="XList")

    def xset(self):
        attr_dict = self._getAttributeDict()
        return XSet(self, attr_dict, naked_type="XSet")

    #------------------------------------------------------------------------------
    # [ type method ] (string)
    #  returns the Naked type extension string that is set in the constructor for each object type
    #------------------------------------------------------------------------------
    def type(self):
        if hasattr(self, '_naked_type_'):
            return self._naked_type_
        else:
            return None


#------------------------------------------------------------------------------
# [[ XString class ]]
#   An inherited extension to the immutable string object that permits attribute assignment
#   Immutable so there is no setter method, attributes must be set in the constructor
#   Python 2: byte string by default, can cast to normalized UTF-8 with XString().unicode() method
#   Python 3: string (that permits unicode) by default, can normalize with XString().unicode() method
#------------------------------------------------------------------------------
class XString(str):
    def __new__(cls, string_text, attributes={}, naked_type='XString'):
        str_obj = str.__new__(cls, string_text)
        if len(attributes) > 0:
            for key in attributes:
                setattr(str_obj, key, attributes[key])
        setattr(str_obj, '_naked_type_', naked_type)
        return str_obj

    #------------------------------------------------------------------------------
    # [ _getAttributeDict method ] (dictionary)
    #  returns a dictionary of the XString instance attributes
    #------------------------------------------------------------------------------
    def _getAttributeDict(self):
        return self.__dict__

    #------------------------------------------------------------------------------
    # [ type method ] (string)
    #  returns the Naked type extension string that is set in the constructor for each object type
    #------------------------------------------------------------------------------
    def type(self):
        if hasattr(self, '_naked_type_'):
            return self._naked_type_
        else:
            return None

    ## TODO: see where + vs. join breakpoint becomes important
    def concat(self, *strings):
        str_list = []
        for x in strings:
            str_list.append(x)
        return "".join(str_list)

    # fastest substring search truth test
    def contains(self, substring):
        return substring in self

    # split the string on one or more delimiters, return list
    # if up to two chars, then uses str.split(), if more chars then use re.split
    def xsplit(self, split_delimiter):
        length = len(split_delimiter)
        if length > 2:
            import re
            split_delimiter = "".join([ '[', split_delimiter, ']' ])
            return re.split(split_delimiter, self)
        elif length > 1:
            delim2 = split_delimiter[1]
            first_list = self.split(split_delimiter[0])
            result_list = []
            for item in first_list:
                for subitem in item.split(delim2):
                    result_list.append(subitem)
            return result_list
        else:
            return self.split(split_delimiter)

    # split the string on one or more characters and return items in set
    def xsplit_set(self, split_delimiter):
        return set(self.xsplit(split_delimiter))

    # str begins with substring - faster than str.startswith()
    def begins(self, begin_string):
        return begin_string in self[0:len(begin_string)]

    # str ends with substring - faster than str.endswith()
    def ends(self, end_string):
        return end_string in self[-len(end_string):]

    # case sensitive wildcard match on the XString (boolean returned)
    def wildcard_match(self, wildcard):
        from fnmatch import fnmatchcase
        return fnmatchcase(self, wildcard)

    # convert string to normalized UTF-8 in Python 2 and 3 (##TODO: convert to XUnicode with attributes?)
    def unicode(self):
        from sys import version_info
        from unicodedata import normalize
        if version_info[0] == 2:
            return normalize('NFKD', self.decode('UTF-8'))
        else:
            return normalize('NFKD', self)


# this version works
class XUnicode:
    def __init__(self, string_text, attributes={}, naked_type='XUnicode'):
        import sys
        import unicodedata
        norm_text = unicodedata.normalize('NFKD', string_text)

        class XUnicode_2(unicode):
            def __new__(cls, the_string_text, attributes={}, naked_type='XUnicode2'):
                str_obj = unicode.__new__(cls, the_string_text)
                if len(attributes) > 0:
                    for key in attributes:
                        setattr(str_obj, key, attributes[key])
                setattr(str_obj, '_naked_type_', naked_type) # set the type to XUnicode2 for Py 2 strings
                return str_obj

        class XUnicode_3(str):
            def __new__(cls, the_string_text, attributes={}, naked_type='XUnicode3'):
                str_obj = str.__new__(cls, the_string_text)
                if len(attributes) > 0:
                    for key in attributes:
                        setattr(str_obj, key, attributes[key])
                setattr(str_obj, '_naked_type_', naked_type) # set the type to XUnicode3 for Py 3 strings
                return str_obj


        if sys.version_info[0] == 2:
            self.obj = XUnicode_2(norm_text, attributes)
            self.norm_unicode = norm_text
            self.naked_u_string = self.obj.encode('utf-8') # utf-8 encoded byte string
        elif sys.version_info[0] == 3:
            self.naked_u_string = XUnicode_3(norm_text, attributes).encode('utf-8') # ?

    def __str__(self):
        # return self.naked_u_string
        return self.obj

    def __repr__(self):
        return self.naked_u_string

    def __getattr__(self, the_attribute):
        return self.obj.__dict__[the_attribute]

    def __cmp__(self, other_string):
        return hash(self.naked_u_string) ==  hash(other_string)
        # TODO: add check for same attributes

    #------------------------------------------------------------------------------
    # [ _getAttributeDict method ] (dictionary)
    #  returns a dictionary of the NakedObject instance attributes
    #------------------------------------------------------------------------------
    def _getAttributeDict(self):
        return self.__dict__

    #------------------------------------------------------------------------------
    # [ type method ] (string)
    #  returns the Naked type extension string that is set in the constructor for each object type
    #------------------------------------------------------------------------------
    def type(self):
        if hasattr(self, '_naked_type_'):
            return self._naked_type_
        else:
            return None


#------------------------------------------------------------------------------
# [[ XTuple class ]]
#
#------------------------------------------------------------------------------
class XTuple(tuple):
    def __new__(cls, the_tuple, attributes={}, naked_type='XTuple'):
        tup_obj = tuple.__new__(cls, the_tuple)
        if len(attributes) > 0:
            for key in attributes:
                setattr(tup_obj, key, attributes[key])
        setattr(tup_obj, '_naked_type_', naked_type)
        return tup_obj

    #------------------------------------------------------------------------------
    # [ _getAttributeDict method ] (dictionary)
    #  returns a dictionary of the NakedObject instance attributes
    #------------------------------------------------------------------------------
    def _getAttributeDict(self):
        return self.__dict__

    #------------------------------------------------------------------------------
    # [ type method ] (string)
    #  returns the Naked type extension string that is set in the constructor for each object type
    #------------------------------------------------------------------------------
    def type(self):
        if hasattr(self, '_naked_type_'):
            return self._naked_type_
        else:
            return None


if __name__ == '__main__':
    pass
    # no = nobj({"version":"1.0.1", "test":"code"})
    # print(no)
    # print(no.version)
    # print(no.test)
    # nl = XList([1, 2, 3, 1, 2, 5], {"version":"1.0.1", "test":"code"})
    # print(nl.count_duplicates())
    # the_list = list(range(5000))
    # nl = XList(the_list)
    # nq = XPriorityQueue()
    # nq.push('test', 5)
    # nq.push('one', 3)
    # nq.push('another', 4)
    # print(nq.pop())
    # print(nq.pop())
    # print(nq.pop())

    # nl = XList([2, 2, 2, 'another'], {'p': 'attribute'})
    # print(nl)
    # print(nl.count_item(2))
    # nq = XQueue(nl, max_length=2)
    # print(nq)

    # xs = XSet({'test', 'true', 'false'}, {'bonus': 'candy', 'test': 'another'})
    # xs += {'bogus', 'yep'}
    # print(xs)

    # xd = XDict({'test2': 0, 'is': 1}, {'a': '1', 'b': '2'})
    # ad = {'test': 0, 'is': 2}
    # ld = xd.intersection(ad)
    # print(ld)
    # xd = xd + ad + ld
    # print(xd.map_to_vals(pr))
    # print(xd.a)
    # print(xd)
    # print(xd.a)
    # print(xd.min_val())
    # print(xd.conditional_map_to_vals(matcher, resulter))

    # nl = XList([ 'test.txt', 'bogus.txt', 'test.py', 'another.rb', 'est.doc', 'est.py' ])
    # print(nl.multi_wildcard_match('*.py|*.txt|*.doc'))

    # xstr = XString("Hey! Cœur It's Bengali ব য,\nand here is some more ২")
    # ustr = xstr.unicode()
    # print(isinstance(ustr, bytes))
    # print(xstr)

