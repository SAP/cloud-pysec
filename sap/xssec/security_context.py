"""
This module is deprecated.
"""
import warnings

from sap.xssec import SecurityContextXSUAA

warnings.warn("Class security_context.SecurityContext is deprecated, "
              "use security_context_xsuaa.SecurityContextXSUAA instead ", DeprecationWarning, stacklevel=2)

SecurityContext = SecurityContextXSUAA
