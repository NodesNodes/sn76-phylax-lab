class Field:
    def __init__(self, name, kind):
        self.name = name
        self.kind = kind


class Struct:
    def __init__(self, *fields):
        self.fields = list(fields)
