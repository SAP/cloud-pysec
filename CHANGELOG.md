# Change Log
All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](http://semver.org/).

The format is based on [Keep a Changelog](http://keepachangelog.com/).

## 3.2.0
### Added

- Support `async` user token requests

## 3.1.0
### Added
	
- Support for tokenexchanges with X.509 certificates managed by XSUAA
- Support for tokenexchanges with manually managed X.509 certificates
- Support for configuration objects that does not provide a clientsecret (but a certificate)

## 3.0.0
### Removed
- Removed support for python 2

### Changed
- Replaced *requests* library with *httpx* for better async support

## 2.1.0

### Added
- Support for token audience

## 2.0.12

### Fixed
- Bug: wrong variable name used for debug logging during token validation

## 2.0.11

### Added
- Support for zone_id and zid.

### Fixed
- Improved jku validation

## 2.0.10

### Changed
- Dependency update for six

## 2.0.9

### Changed
- Fix for SAP_JWT_TRUST_ACL; fails after first non-matching entry.

## 2.0.8

### Changed
- Fix for broker plan; adapt fix from node/xssec version 2.1.14

## 2.0.7

### Changed
- Use sap_py_jwt as default library for decoding

### Added
- Implement resilience: add retry for key retrieval

## 2.0.6

### Fixed
- Added cryptography as dependency for pyjwt

## 2.0.5

### Fixed
- XSA fix: Do not require uaadomain in VCAP_SERVICES but use local verificationkey

## 2.0.4

### Fixed
- Dependecy for automatic pip install repaired

## 2.0.2

### Added
- Optional signature validation with pyjwt or sap-py-jwt

## 2.0.1

### Added
- Load key from token_keys and use KeyCache

## 2.0.0

### Added
- Initial version.
