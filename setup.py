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
    url='https://github.com/SAP/cloud-pysec',
    version=VERSION.strip(),
    author='SAP SE',
    description=('SAP Python Security Library'),
    packages=find_packages(include=['sap*']),
    data_files=[('.', ['version.txt', 'CHANGELOG.md'])],
    test_suite='tests',
    install_requires=[
        'deprecation>=2.1.0',
        'httpx>=0.16.1',
        'urllib3',
        'six>=1.11.0',
        'pyjwt>=2.0.1',
        'cachetools>=4.2.4',
        'cryptography>=35.0.0'
    ],
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    classifiers=[
        # http://pypi.python.org/pypi?%3Aaction=list_classifiers
        "Development Status :: 5 - Production/Stable",
        "Topic :: Security",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Operating System :: POSIX :: BSD",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
)
