""" xssec setup """
import codecs
from os import path
from setuptools import setup, find_packages

CURRENT_DIR = path.abspath(path.dirname(__file__))
README_LOCATION = path.join(CURRENT_DIR, 'README.md')
VERSION = ''
with open(path.join(CURRENT_DIR, 'version.txt'), 'r') as version_file:
     VERSION = version_file.read()

with codecs.open(README_LOCATION, 'r', 'utf-8') as readme_file:
    LONG_DESCRIPTION = readme_file.read()

setup(
    name='sap_xssec',
    version=VERSION.strip(),
    author='SAP',
    description=('SAP Python Security Library'),
    packages=find_packages(include=['sap*']),
    data_files = [('.', ['version.txt', 'CHANGELOG.md'])],
    test_suite='tests',
    install_requires=[
        'requests==2.20.0',
        'six==1.11.0',
        'sap_py_jwt>=1.1.1'
    ],
    long_description=LONG_DESCRIPTION,
    classifiers=[
        # http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
