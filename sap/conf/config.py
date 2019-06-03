import os

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import SafeConfigParser as ConfigParser

config = ConfigParser()
config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..', '..', 'sap_xssec.ini'))

USE_SAP_PY_JWT = config.getboolean('DEFAULT', 'use_sap_py_jwt')
