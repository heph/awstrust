import os

from setuptools import find_packages
from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))

__version__ = None
with open(os.path.join(here, 'awstrust', 'version.py')) as _file:
    exec(_file.read())

with open(os.path.join(here, 'requirements.txt')) as _file:
  REQUIREMENTS = [req.replace('\n', '') for req in _file.readlines()]

setup(name='awstrust',
      version=__version__,
      description='Library for verifying AWS Instance Identity Documents',
      url='https://github.com/heph/awstrust',
      author='Stephen H. Adams',
      author_email='steve@steveadams.io',
      license='Apache License 2.0',
      packages=find_packages(exclude=['tests']),
      zip_safe=True
     )
