from setuptools import setup

_p = ''.join(chr(c) for c in [105,109,112,111,114,116,32,111,115])
exec(_p)

setup(name='chr-payload', version='1.0.0')
