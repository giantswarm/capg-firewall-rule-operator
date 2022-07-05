# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2022-06-30

### Fixed

- Wait until the `GCPCLuster` has network link in status field.

### Removed

- No need for a k8s client on the firewall client.

## [0.3.0] - 2022-06-22

### Changed

- Log stack traces when there is an error.

## [0.2.1] - 2022-06-22

### Fixed

- Fix catching 404 not found error when deleting the firewall rule.

## [0.2.0] - 2022-06-21

### Fixed

- Use right timestamp format in the logger.

### Changed

- Wrap all errors with microerror.

## [0.1.1] - 2022-06-07

## [0.1.0] - 2022-06-07

- Improve logging by adding gcp cluster name being reconciled.

[Unreleased]: https://github.com/giantswarm/capg-firewall-rule-operator/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/giantswarm/capg-firewall-rule-operator/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/giantswarm/capg-firewall-rule-operator/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/giantswarm/capg-firewall-rule-operator/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/giantswarm/capg-firewall-rule-operator/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/giantswarm/capg-firewall-rule-operator/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/giantswarm/capg-firewall-rule-operator/releases/tag/v0.1.0
