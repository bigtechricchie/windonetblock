# WindoNetBlock

**Application-aware network control and process visibility for Windows**

WindoNetBlock is a Go-based Windows security tool for application-aware network control, process visibility, and auditable allow/block policies.

Built by Edward Siwek.

## Status

WindoNetBlock is under active development.

The project is being developed incrementally with an emphasis on:

- Windows security fundamentals
- least privilege
- explicit application identity
- deterministic network policy
- auditable security decisions
- documented Windows APIs
- clear failure behaviour

## Security scope

WindoNetBlock is intended to provide application process visibility and application-aware network policy enforcement.

It is not antivirus software.

A valid digital signature does not prove that software is safe, and unsigned software is not automatically malicious.

## Current state

WindoNetBlock can currently:

- inspect its own process ID and executable path;
- calculate a SHA-256 digest for the file currently found at its observed executable path;
- inspect its current Windows user SID, account name, and mandatory integrity level;
- take a Windows process snapshot;
- enumerate current process IDs, parent process IDs, and executable names;
- resolve full executable paths where Windows permits access;
- inspect per-process user SID, account name, and mandatory integrity level where Windows permits access;
- preserve process snapshot information when path or security-context inspection is unavailable.

This is observation only.

The SHA-256 value identifies the file content read from the observed executable path at inspection time. It does not by itself prove publisher identity, trustworthiness, or that the file could not change before or after inspection.

WindoNetBlock does not currently provide:

- continuous process monitoring;
- executable signature verification;
- per-process executable SHA-256 evidence;
- executable hash caching or file-identity validation;
- network monitoring;
- policy enforcement;
- firewall modification;
- a privileged service;
- a graphical interface.
