import pickle


def load(blob):
    return pickle.loads(blob)


def store(obj):
    return pickle.dumps(obj)
