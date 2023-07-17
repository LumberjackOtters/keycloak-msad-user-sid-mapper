# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2023-07-17

### Added

- New mapper for LDAP compatible with [Keycloak](https://www.keycloak.org/) starting from version 21.
- The mapper is available under mapper selection, with the name: ```msad-user-sid-ldap-mapper```
- It will retrieve the SID of the user object from the ActiveDirectory under a human-readable form.
