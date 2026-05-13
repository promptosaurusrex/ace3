# ACE3 Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project (tries to) adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.47] - 2026-05-13

- [Makes it more clear how Phishkit retrieves data](https://github.com/ACE-Collective/ace3/pull/217)
- [Skips unresolved interpolated values](https://github.com/ACE-Collective/ace3/pull/218)
- [Replaces legacy interpolation with jinja](https://github.com/ACE-Collective/ace3/pull/219)
- [Fixes missing signature_id observables](https://github.com/ACE-Collective/ace3/pull/220)

## [3.0.46] - 2026-05-12

- [Adds 'correlated' tag to correlated hunt alerts](https://github.com/ACE-Collective/ace3/pull/212)
- [Fixes some cartesian product bugs](https://github.com/ACE-Collective/ace3/pull/213)
- [Handle both types of timeouts for Phishkit](https://github.com/ACE-Collective/ace3/pull/214)
- [Fixes some minor Phishkit issues](https://github.com/ACE-Collective/ace3/pull/215)

## [3.0.45] - 2026-05-11

- [Adds generic support for source_options](https://github.com/ACE-Collective/ace3/pull/207)
- [Correlation Trace UI improvements](https://github.com/ACE-Collective/ace3/pull/208)
- [Fix issue with phishkit runtime error being treated as a module level error](https://github.com/ACE-Collective/ace3/pull/209)

## [3.0.44] - 2026-05-07

- [Fixes several rfc822 parsing bugs](https://github.com/ACE-Collective/ace3/pull/203)
- [Adds Remediation Timeline table to alert page](https://github.com/ACE-Collective/ace3/pull/205)
- [Opts WHOIS analysis module into cache writes](https://github.com/ACE-Collective/ace3/pull/204)

## [3.0.43] - 2026-05-05

- [Observable type inheritance](https://github.com/ACE-Collective/ace3/pull/193)
- [Adds email address fqdn module](https://github.com/ACE-Collective/ace3/pull/194)
- [Fixes observable/detection point scrolling](https://github.com/ACE-Collective/ace3/pull/195)
- [Fixes JS deobfuscator issues and recurses](https://github.com/ACE-Collective/ace3/pull/196)
- [configuration defined correlated hunt query sources](https://github.com/ACE-Collective/ace3/pull/198)
- [Bumps urlfinderlib version](https://github.com/ACE-Collective/ace3/pull/199)
- [Adds siblings scope to observable modifier](https://github.com/ACE-Collective/ace3/pull/200)

## [3.0.42] - 2026-05-04

- [Show a per-alert correlation trace](https://github.com/ACE-Collective/ace3/pull/185)
- [Adds newly registered domain system](https://github.com/ACE-Collective/ace3/pull/186)
- [Implements second phase of analysis caching](https://github.com/ACE-Collective/ace3/pull/149)
- [Moves analysis cache config into dedicated section](https://github.com/ACE-Collective/ace3/pull/187)
- [Add support for per-group suppression in Hunt class](https://github.com/ACE-Collective/ace3/pull/188)
- [Adds Jinja interpolation for hunt name](https://github.com/ACE-Collective/ace3/pull/189)
- [Default time fields and time format by source for correlated queries](https://github.com/ACE-Collective/ace3/pull/190)
- [Fixed logging issue](https://github.com/ACE-Collective/ace3/pull/191)


## [3.0.41] - 2026-04-28

- [Migrates Flask 'common' API endpoints to FastAPI](https://github.com/ACE-Collective/ace3/pull/164)
- [Fixes bugs in detection chains](https://github.com/ACE-Collective/ace3/pull/180)
- [Adds multiple time ranges support to hunt validator](https://github.com/ACE-Collective/ace3/pull/181)
- [Adds multi-click support to Phishkit](https://github.com/ACE-Collective/ace3/pull/182)
- [Updates observable modifier docs](https://github.com/ACE-Collective/ace3/pull/183)

## [3.0.40] - 2026-04-24

- [Indent guide refinement](https://github.com/ACE-Collective/ace3/pull/170)
- [Adds Detection Chains visualization](https://github.com/ACE-Collective/ace3/pull/172)
- [Phishkit dynamic wait](https://github.com/ACE-Collective/ace3/pull/173)
- [Fixes the "Add" button on Manual Analysis page](https://github.com/ACE-Collective/ace3/pull/174)

## [3.0.39] - 2026-04-23

- [Fixes manage alerts page horizontal scrolling](https://github.com/ACE-Collective/ace3/pull/166)
- [Fixes email parsing bug](https://github.com/ACE-Collective/ace3/pull/165)

## [3.0.38] - 2026-04-22

- [Fixes bug when using field_lookup_type: dot](https://github.com/ACE-Collective/ace3/pull/160)
- [Moves signatures to bind mount for local dev](https://github.com/ACE-Collective/ace3/pull/161)
- [Enables fqdn_analyzer by default in correlation mode](https://github.com/ACE-Collective/ace3/pull/162)

## [3.0.37] - 2026-04-22

- [Add resource limits configuration and implement container reaper in phishkit](https://github.com/ACE-Collective/ace3/pull/157)

## [3.0.36] - 2026-04-21

- [Adds 'Needs Research' functionality](https://github.com/ACE-Collective/ace3/pull/150)
- [Preserve whitespace in hunt instructions](https://github.com/ACE-Collective/ace3/pull/151)
- [Adds descendants functionality to observable modifier](https://github.com/ACE-Collective/ace3/pull/152)
- [Implement lock-dependent UI updates and status display for alerts](https://github.com/ACE-Collective/ace3/pull/153)
- [Various Phishkit adjustments to handle wss](https://github.com/ACE-Collective/ace3/pull/154)
- [Fixes for JS sandbox recorder proxy](https://github.com/ACE-Collective/ace3/pull/155)

## [3.0.35] - 2026-04-17

- [Minor improvements for adding phishkit MARKER URL observables](https://github.com/ACE-Collective/ace3/pull/144)
- [Various JS deobfuscation improvements](https://github.com/ACE-Collective/ace3/pull/145)
- [Makes command_line analysis module a bit more robust](https://github.com/ACE-Collective/ace3/pull/146)

## [3.0.34] - 2026-04-15

- [Require observable modifier rule uuid](https://github.com/ACE-Collective/ace3/pull/138)
- [Exclude OCR/QR analysis from extracted HTML data URLs](https://github.com/ACE-Collective/ace3/pull/136)
- [Replace Synchrony with custom JS sandbox analysis module](https://github.com/ACE-Collective/ace3/pull/135)

## [3.0.33] - 2026-04-14

- [correlated hunts](https://github.com/ACE-Collective/ace3/pull/126)

## [3.0.32] - 2026-04-13

- [Allow hunts to override included observable_mapping entries](https://github.com/ACE-Collective/ace3/pull/130)
- [Adds phishkit's MARKER URL values as url observables](https://github.com/ACE-Collective/ace3/pull/131)

## [3.0.31] - 2026-04-13

- [Implements phase 1 of analysis caching](https://github.com/ACE-Collective/ace3/pull/125)

## [3.0.30] - 2026-04-13

- [consolidated signature repos](https://github.com/ACE-Collective/ace3/pull/127)

## [3.0.29] - 2026-04-10

- [Extract base64-encoded form fields and JavaScript](https://github.com/ACE-Collective/ace3/pull/123)

## [3.0.28] - 2026-04-09

- [Adds generic sandbox submissions table](https://github.com/ACE-Collective/ace3/pull/117)
- [Copy observable value, not display_value](https://github.com/ACE-Collective/ace3/pull/118)
- [Show more/less comments on manage alerts page](https://github.com/ACE-Collective/ace3/pull/119)
- [Add uri_path observable if not valid url](https://github.com/ACE-Collective/ace3/pull/120)
- [Uses display_type for observable sort order](https://github.com/ACE-Collective/ace3/pull/121)

## [3.0.27] - 2026-04-07

- [Phishkit web workers fixes](https://github.com/ACE-Collective/ace3/pull/115)

## [3.0.26] - 2026-04-07

- [Update pivot link icon handling in alert template to support external URLs](https://github.com/ACE-Collective/ace3/pull/113)
- [Pins ilspy to last known working version for .NET 8.0](https://github.com/ACE-Collective/ace3/pull/112)

## [3.0.25] - 2026-04-07

- [Observable modifier rules match by display_type/value](https://github.com/ACE-Collective/ace3/pull/110)

## [3.0.24] - 2026-04-03

- minor bugfixes and improvements

## [3.0.23] - 2026-04-01

- [Adds support for ignoring observables with observable modifier rules](https://github.com/ACE-Collective/ace3/pull/100)
- [Phishkit config fixes](https://github.com/ACE-Collective/ace3/pull/106)

## [3.0.22] - 2026-03-31

- [Makes get_alert_meta endpoint a bit more robust](https://github.com/ACE-Collective/ace3/pull/101)
- [Adds support for adding an observable to many alerts at once](https://github.com/ACE-Collective/ace3/pull/102)
- phishkit bugfixes and enhancements

## [3.0.21] - 2026-03-30

- [Adds breadcrumb navigation to ACE alerts](https://github.com/ACE-Collective/ace3/pull/94)
- [Adds 'interesting' observable support](https://github.com/ACE-Collective/ace3/pull/95)
- [Adds observable comment support](https://github.com/ACE-Collective/ace3/pull/96)

## [3.0.20] - 2026-03-25

- [bumps urlfinderlib version](https://github.com/ACE-Collective/ace3/pull/92)
- [refactors phishkit to use config file](https://github.com/ACE-Collective/ace3/pull/91)
- [preserves whitespace and new lines when displaying comments](https://github.com/ACE-Collective/ace3/pull/90)
- [fix tag display for alerts on Event page](https://github.com/ACE-Collective/ace3/pull/89)
- [skips adding unresolved interpolated tags](https://github.com/ACE-Collective/ace3/pull/88)
- [phishkit anti-bot improvements](https://github.com/ACE-Collective/ace3/pull/87)

## [3.0.19] - 2026-03-19

- [Phishkit proxy fallback](https://github.com/ACE-Collective/ace3/pull/85)
- [fix issue with partial JSON reads mid-write](https://github.com/ACE-Collective/ace3/pull/84)

## [3.0.18] - 2026-03-18

- [switch to per-type limit on max observable count](https://github.com/ACE-Collective/ace3/pull/82)
- [add a step to upgrade install packages at build](https://github.com/ACE-Collective/ace3/pull/81)
- [fix issue with BOM in 7bit encoding](https://github.com/ACE-Collective/ace3/pull/80)

## [3.0.14] - 2026-03-13

- [Jinja2 support for summary details section](https://github.com/ACE-Collective/ace3/pull/72)

## [3.0.13] - 2026-03-13

- [Implement handling for deleted failed YAML files in HuntManager](https://github.com/ACE-Collective/ace3/pull/70)
- [Adds proxy support to Phishkit and fixes user agent bugs](https://github.com/ACE-Collective/ace3/pull/68)
- [Adjusts order of Docker layers for more resilient caching](https://github.com/ACE-Collective/ace3/pull/69)
- [hunt loading adjustment](https://github.com/ACE-Collective/ace3/pull/71)

## [3.0.12] - 2026-03-11

- [Adds has_yara_meta_tags to observable modifier](https://github.com/ACE-Collective/ace3/pull/66)

## [3.0.8] - 2026-03-09

- [Adds support for multiple time ranges in Splunk hunts and API analysis modules](https://github.com/ACE-Collective/ace3/pull/61)

## [3.0.6] - 2026-03-05

- [Phishkit metrics + Fluent Bit](https://github.com/ACE-Collective/ace3/pull/58)

## [3.0.6] - 2026-03-05

- [Phishkit metrics + Fluent Bit](https://github.com/ACE-Collective/ace3/pull/58)

## [3.0.5] - 2026-03-04

- [Updates Docker images to use Trixie and related fixes](https://github.com/ACE-Collective/ace3/pull/56)

## [3.0.4] - 2026-03-04

- [Unified Hunt & API Analysis Module Refactoring](https://github.com/ACE-Collective/ace3/pull/54)

## [3.0.3] - 2026-03-03

- Updates remaining places that used static VALID_OBSERVABLE_TYPES list
- dependency upgrades
    - markdown==3.10.2
    - pytz==2026.1.post1
    - SQLAlchemy==2.0.48
    - urlfinderlib==0.20.1
    - fastapi==0.135.1

## [3.0.2] - 2026-03-02

- minor bugfixes

## [3.0.1] - 2026-02-28

- summary detail processing for `QueryHunt` with `SummaryDetailConfig` for grouped/ungrouped details, format validation, and limit enforcement
- adds support for analysis module config propert default_collapsed 
- adds support for the new meta tagging for yara rules as defined in `YARA_META_TAGS.md`.
- added logo source files and adjusted title to include version and svg for favicon

## [3.0.0] - 2026-02-27

- integration support
- phishkit scanning support, which doubles as a web crawler / renderer
- support for S3-like storage with MinIO
- direct support for git repos with service to manage
- FastAPI based v2 of API
- massive refactoring
- updated to the latest version of yara
- using new `yara_scanner_v2` project (fixed support for include directive)
- manage email archives database by partition
- build jtr as part of the image
- removed need for custom yara build
- updated to officeparser3
- fixed issues with crypto usage
- switched to YAML for configuration
- fixed authentication issues with some of the exposed services
- deal with ipv6 (hunter trying to parse ipv4 as ipv6)
- fix the "send to" system
- fix the remediation system (call should not block like it does)
- work goes to data directory first, then worker moves work into "work directory" if enabled, when the worker starts
- attachment names are now logged correctly for phishfinder logs
- unravel python code and achieve high test coverage

## [1.0.0] - 2025-07-20

- initial port for ace v1
