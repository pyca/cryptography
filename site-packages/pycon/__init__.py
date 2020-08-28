__version__ = '0.0.2'

def _addindent(s_, numSpaces):
    s = s_.split('\n')
    if len(s) == 1:
        return s_
    s = [(numSpaces * ' ') + line for line in s]
    s = '\n'.join(s)
    return s

class Container(object):
    def __init__(self, **kwargs):
        self.__dict__.update(**kwargs)
        self.__unroll()

    def __iter__(self):
        for key in self.__dict__:
            yield key

    def __setitem__(self, key, value):
        self.__dict__[key] = value

    def __contains__(self, item):
        return item in self.__dict__

    def __getitem__(self, item):
        if item not in self.__dict__:
            return None
        return self.__dict__[item]

    def __getattr__(self, item):
        return self.__getitem__(item)

    def __str__(self):
        tmpstr = "("
        leading_n = 2
        tmpstr += '\n'
        for key in self.__dict__:
            x = self.__dict__[key]
            if isinstance(x, Container):
                tmpstr += '\n'.join([" " * leading_n + "." + key + s.lstrip()
                                     for s in x.__str__().split('\n')][1:-1])
            else:
                tmpstr += " " * leading_n + "." + key + " = " + str(x)
            tmpstr += "\n"
        return tmpstr + ")"

    def __repr__(self):
        leadingstr = "(\n"
        leading_n = len(leadingstr)
        tmpstr = ""
        for key in self.__dict__:
            x = self.__dict__[key]
            tmpstr += key + ": "
            if isinstance(x, Container):
                tmpstr += '(\n'
                tmpstr += hparam.__repr__()[leading_n:-2]
                tmpstr += '\n)'
            else:
                tmpstr += str(x)
            tmpstr += '\n'
        if len(tmpstr) != 0:
            tmpstr = _addindent(tmpstr[:-1], 2)
        return leadingstr + tmpstr + "\n)"

    def __unroll(self):
        for key in self.__dict__:
            if type(self.__dict__[key]) is dict:
                self.__dict__[key] = Container(**self.__dict__[key])

    def to_dict(self):
        res_dict = {}
        for key in self.__dict__:
            if isinstance(self.__dict__[key], Container):
                res_dict[key] = self.__dict__[key].to_dict()
            else:
                res_dict[key] = self.__dict__[key]
        return res_dict

    def items(self):
        for item in self.__dict__.items():
            yield item
