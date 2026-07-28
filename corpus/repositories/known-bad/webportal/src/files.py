import os

ROOT = "/srv/files"


def read(name):
    return open(ROOT + "/" + name, encoding="utf-8").read()
