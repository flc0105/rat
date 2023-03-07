import importlib.metadata
import sys
from platform import python_version

print(f'Python version: {python_version()}\n')

if sys.version_info < (3, 8, 0):
    sys.stderr.write("You need python 3.8 or later to run this script\n")
    exit(1)

for distribution in importlib.metadata.distributions():
    print(distribution.metadata['Name'], distribution.metadata['Version'])
