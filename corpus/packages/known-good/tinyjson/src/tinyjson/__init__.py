import json


def loads(text):
    return json.loads(text)


def dumps(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))
