class CBC(object):
    name = "CBC"

    def __init__(self, initialization_vector, padding):
        super(CBC, self).__init__()
        self.initialization_vector = initialization_vector
        self.padding = padding
