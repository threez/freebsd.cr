# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- Bumped the `ameba` dev dependency from `~> 1.6.0` to `~> 1.7.0`.

### Fixed

- Resolved new `ameba` 1.7.0 lint findings: added spacing around macro
  expressions (`Lint/WhitespaceAroundMacroExpression`) across the `casper`
  bindings, removed redundant `nil` returns in `Capsicum::Directory`
  (`Style/RedundantNilInControlExpression`), switched a multi-line curly
  block to `do`/`end` in a spec (`Style/MultilineCurlyBlock`), dropped an
  unused `rescue` variable in a sandbox spec fixture
  (`Lint/UnusedRescueVariable`), and removed a now-unneeded
  `ameba:disable Metrics/CyclomaticComplexity` directive
  (`Lint/UnneededDisableDirective`).
