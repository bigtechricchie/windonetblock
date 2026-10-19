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

- inspect its own process ID, creation time, and executable path;
- retrieve a Windows file identity for its current executable using the volume serial number and 128-bit file ID;
- calculate a SHA-256 digest for the file currently found at its observed executable path;
- verify the current executable with the Windows Authenticode policy provider without network retrieval;
- inspect its current Windows user SID, account name, and mandatory integrity level;
- take a Windows process snapshot;
- enumerate current process IDs, parent process IDs, executable names, and creation times where Windows permits access;
- resolve full executable paths where Windows permits access;
- retrieve per-process Windows file identity where the executable file is accessible;
- calculate per-process executable SHA-256 evidence where the executable file is readable;
- reuse SHA-256 results within a single snapshot when Windows file identity, file size, and last-write time are unchanged;
- verify per-process executable Authenticode status where the executable file is accessible;
- reuse Authenticode evidence within a single snapshot when Windows file identity, file size, and last-write time are unchanged;
- inspect per-process user SID, account name, and mandatory integrity level where Windows permits access;
- preserve process snapshot information when timing, path, identity, hash, signature, or security-context inspection is unavailable.

This is observation only.

A process ID is not treated as a durable process-instance identity. Windows can reuse PIDs after processes exit. The observed process creation time provides an additional discriminator so future lifecycle correlation can use the pair of process ID and creation time rather than PID alone.

A Windows file identity is represented by the volume serial number and 128-bit file ID returned by `GetFileInformationByHandleEx` with `FileIdInfo`. This distinguishes the underlying file from its path and provides a stronger identity primitive for cache and future policy work.

A SHA-256 value identifies the file content read from an observed executable path at inspection time. It does not by itself prove publisher identity, trustworthiness, or that the file could not change before or after inspection.

The current SHA-256 and Authenticode caches exist only for one process snapshot. They correlate evidence using Windows file identity, file size, and last-write time, and reject evidence when that file state changes during inspection.

The current Authenticode checks use the Windows software-publisher trust policy with UI disabled and cache-only URL retrieval. A `Trusted` result means Windows accepted the file for that policy using locally available trust information. It does not mean that WindoNetBlock has established that the software is safe. `Unsigned` and `Not trusted` are kept distinct, and the raw WinVerifyTrust status code is retained.

WindoNetBlock does not currently provide:

- continuous process monitoring;
- signer or publisher certificate extraction;
- online revocation checking;
- persistent executable hash or signature caching;
- network monitoring;
- policy enforcement;
- firewall modification;
- a privileged service;
- a graphical interface.
