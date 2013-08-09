class CBC(object):
    def __init__(self, initialization_vector, padding):
        super(CBC, self).__init__()
        self.initialization_vector = initialization_vector
        self.padding = padding
