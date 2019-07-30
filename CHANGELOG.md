# Change Log
All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](http://semver.org/).

The format is based on [Keep a Changelog](http://keepachangelog.com/).

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
