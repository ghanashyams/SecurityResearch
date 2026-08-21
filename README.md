# SecurityResearch

Windows security research and defensive tooling — kernel-level monitoring and detection built directly against ETW and the Filter Manager, in native C++.

## Modules

- **ETW Kernel Monitoring** — Real-time ETW consumer on a custom trace session, enabling Process, File I/O, and Registry kernel providers individually via `EnableTraceEx2` and parsing event payloads with TDH.
- **MiniFilter Driver** — Kernel-mode minifilter that intercepts file writes and hands the content to a user-mode companion app for scanning over a filter communication port, allowing or blocking the write based on the scan verdict (with a configurable fail-open/fail-closed policy on scanner timeout).
- **Remote Thread Injection** — ETW-based detector for cross-process `CreateRemoteThread` activity: resolves thread start addresses to loaded modules and named exports, verifies Authenticode signatures (including catalog-signed files), and filters out the common benign patterns (process startup, sandboxed multi-process apps, kernel pico-processes) that would otherwise look identical to real injection.

Each module builds standalone; see the source files for build instructions.
