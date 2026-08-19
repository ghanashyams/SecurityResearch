# Remote Thread Detection Tool

A kernel-level ETW (Event Tracing for Windows) monitoring utility that detects cross-process thread creation and identifies whether injected threads start in legitimate code or injected/shellcode regions.

## Overview

**remote_thread_detect.cpp** uses Event Tracing for Windows (ETW) via the Krabs library to monitor `CreateRemoteThread()` activity in real-time. It:

- **Detects** remote thread creation across processes (where caller PID ≠ target PID)
- **Resolves** both caller and target processes to their full executable paths
- **Analyzes** the thread's entry point (`Win32StartAddr`) against loaded modules in the target process
- **Identifies** injected code by flagging thread starts in unmapped memory regions

This makes it immediately clear whether a remote thread is starting in a legitimate loaded DLL/EXE or in private (injected) memory — a key signal for detecting code injection attacks.

## Key Features

- **Real-time monitoring** of kernel thread creation events
- **Process name caching** from process creation/termination events
- **False-positive filtering** for two common benign patterns that otherwise look identical to injection by PID pattern alone:
  - a process's own initial thread, created by its parent as part of normal `CreateProcess()`
  - threads created inside kernel-mode minimal/pico processes (e.g. `MemCompression`), which have no usermode context and can't be a `CreateRemoteThread()` target in the first place
- **Module tracking** via image-load provider (tracks all DLL/EXE loads per process)
- **Smart address resolution** that probes multiple data types to handle cross-Windows-version schema variations
- **Deferred event resolution** with 300ms grace period to account for cross-CPU ETW delivery ordering
- **Full event payload inspection** — all raw event properties are captured and displayed
- **Verbose mode** (`-v` / `--verbose`) to include system process (PID 4) activity and the two filtered false-positive categories above (each labeled distinctly, not as `[!] Remote thread created`)
- **Same-image labeling** (always shown, not `-v`-gated) for events where the caller and target are the same executable — common in sandboxed multi-process apps (Chromium-based browsers, etc.) — labeled `[?]` rather than suppressed, since "same trusted image" is a weak, spoofable signal, not proof; matches regardless of whether either path is in drive-letter or NT device-path form
- **Optional Authenticode verification** (`-s` / `--verify-signatures`) checking whether the caller and target are validly signed, and by the same publisher — including catalog-signed files (most of Windows itself), which need a separate lookup path from embedded-signed ones
- **Signature-corroborated same-image suppression** (with `-s`) — a same-image event backed by a valid, matching signature on both sides is promoted from the always-shown `[?]` label to the same suppressed-by-default treatment as the two structural filters
- **Cross-component same-publisher labeling** (with `-s`) — different binaries, matching valid signer (e.g. one vendor's own service launching its own helper process) — labeled `[?]`, not suppressed; a shared publisher across *different* files is weaker evidence than a shared publisher on the *same* file
- **svchost.exe service-group context** — when the caller is `svchost.exe`, its `-k <service group>` argument is read off its own command line and shown alongside the event, since "svchost.exe" alone doesn't say which of the dozens of services it might be hosting (some of which, like Task Scheduler and the Windows Update Orchestrator, routinely and legitimately create threads in arbitrary third-party executables)
- **Tuned trace buffers**, scaled to CPU count, to reduce the risk of ETW dropping events under the combined process/thread/image-load volume this session watches system-wide
- **EventsLost tracking**, logged every 30 seconds, so a run that's silently dropping events under load is visible instead of invisible
- **Clean shutdown** via Ctrl+C handler that properly stops the ETW session

## Architecture & How It Works

### Three ETW Providers

1. **Process Provider** — Captures process start/end events to build a PID → executable path mapping
2. **Thread Provider** — Captures thread start events, including remote thread creation
3. **Image Load Provider** — Tracks all DLL/EXE loads per process to build per-PID module lists

### Deferred Resolution Pattern

When a remote thread event arrives, we don't immediately resolve its `Win32StartAddr` against the target's loaded modules. Why? ETW only guarantees event ordering *per-CPU*, not globally. A newly spawned process's Thread-Start event can arrive *before* its own Image-Load events if they're dispatched on different CPU cores.

Instead:
1. **Capture** the raw event data immediately (PID, Win32StartAddr, payload)
2. **Queue** it with a due-time 300ms in the future
3. **Wait** in a background resolver thread for that grace period
4. **Resolve** against the by-then-populated module cache
5. **Print** the result with accurate module information

This eliminates false-positive "unbacked" alerts that would occur with synchronous resolution.

### Address Type Robustness

Address-sized fields (`ImageBase`, `ImageSize`, `Win32StartAddr`) appear under different TDH types across Windows builds and provider versions:
- `POINTER`
- `UINT64`
- `UINT32`

The code probes each type in sequence until one parses successfully, swallowing exceptions even in debug builds so that a wrong guess is a normal, silent event.

### Main-Image Confirmation

Before reporting an address as `<UNBACKED -- possible injected code>`, the tool confirms that the target process's own main executable has been recorded in the module cache. This prevents false positives during process startup when early modules (e.g., ntdll.dll) arrive before the main image.

### Initial-Thread Filtering

Every process's *first* thread is created by its parent, as part of `CreateProcess()` — the parent's own thread executes the kernel code that creates the new process object and its initial thread, before the child ever runs an instruction. The resulting kernel event always has caller PID (the parent) ≠ target PID (the child), which is indistinguishable from real injection by PID pattern alone. Left unfiltered, this fires on **every process launch**, making the tool nearly unusable on any real workload.

The tool tracks each process's `ParentId` and creation timestamp (from the process provider's Start/DCStart events). A thread-create event is treated as "just the process being born," and suppressed by default, only when *both*:
- the target's recorded parent matches the event's caller PID, **and**
- the thread-create event falls within 500ms of the process-create event

Requiring the tight time window (not just the PID match) is what distinguishes normal process startup from a parent injecting into an *already-running* child later (e.g. process hollowing) — the latter happens well outside that window.

### Kernel-Mode Target Filtering

Some ETW-visible "processes" — `MemCompression`, `Secure System`, `Registry` — are kernel-mode minimal/pico processes: internal containers used by the memory manager or kernel, with no executable image and no usermode context. The kernel (e.g. the Store Manager, driven by the SysMain service hosted in some `svchost.exe`) routinely creates worker threads inside them, which again looks exactly like cross-process injection by PID pattern.

It isn't, and structurally can't be: `CreateRemoteThread()`/`NtCreateThreadEx()` from usermode can only point a thread at a usermode address. A thread with no usermode stack or TEB was created directly by kernel code — a path no usermode injection technique can reach. Rather than hardcode the handful of known pico-process names, the tool checks the actual invariant: a real usermode thread always has a nonzero `UserStackBase` and `TebBase`, allocated before it runs its first instruction. When both are zero, the target is a kernel-mode container, and Win32StartAddr resolution against the module cache is skipped entirely — it would never succeed, since these targets never load a usermode image.

### Same-Image Labeling (Not a Filter)

Sandboxed multi-process applications — Chromium-based browsers are the most common example — routinely have their own broker/main process create a thread inside a child process of the *same* executable, as part of legitimate sandbox setup (job objects, tokens, warm-up). That produces exactly the same caller-PID-≠-target-PID shape as injection.

Unlike the two filters above, this isn't suppressed, for a specific reason: "caller and target share an executable path" is not a structural invariant the kernel enforces — it's trivially satisfiable by an attacker who spawns their own copy of a trusted binary (e.g. `msedgewebview2.exe --type=whatever`) as a child and injects into it. Masquerading via an already-trusted path is a known evasion technique specifically *because* rules like "same trusted image = safe" exist. So this case is labeled distinctly — `[?] Same-image parent->child thread (common in sandboxed multi-process apps; not auto-verified)` — so it doesn't get confused with an unreviewed `[!] Remote thread created`, but it's always shown, not `-v`-gated.

The comparison itself has to normalize paths before comparing, not compare the raw strings: the exact same file can be recorded in either drive-letter form (`C:\Users\...\claude.exe`, from CommandLine parsing) or NT device-path form (`\Device\HarddiskVolume4\Users\...\claude.exe`, from the `resolve_process_path()` fallback), depending purely on which one happened to resolve first — caller and target can easily end up in different forms for the identical binary. `strip_volume_prefix()` strips whichever volume-identifying prefix is present before comparing, so a same-image case doesn't get missed just because one side went through a different resolution path than the other.

### Optional Authenticode Verification (`-s` / `--verify-signatures`)

"`Win32StartAddr` resolves to a known module" is a necessary check but not a sufficient one for legitimacy — `inject_test.py`'s own `loadlibrary` mode proves this directly: real `CreateRemoteThread` injection via `kernel32!LoadLibraryA` *also* resolves cleanly to a known module. Whether the caller and target are both validly signed, and by the same publisher, is different and harder-to-fake evidence — it doesn't depend on guessing what "normal" looks like from PID or address patterns.

When enabled, the resolver thread calls `WinVerifyTrust` on both the caller's and target's executable path and prints:

```
    Caller signature: valid (Microsoft Corporation)
    Target signature: valid (Microsoft Corporation)
    Signer match: yes
```

or `unsigned/invalid` / `unavailable (process path unknown)` as appropriate. This is opt-in and off by default for two reasons:
- **Latency.** `WinVerifyTrust` does real cryptographic and certificate-chain work per file. Revocation checking is deliberately disabled (`WTD_REVOKE_NONE`) to avoid blocking on the network per event — a meaningful weakening (it checks "chain and embedded signature are valid," not "still valid right now"), but the right tradeoff for a best-effort triage signal that has to stay usable offline.
- **It runs on the resolver thread, never the ETW callback thread** — same reasoning as everything else that's deferred: blocking the callback thread risks `EventsLost` (see below), and cryptographic verification is exactly the kind of unpredictable-latency work that doesn't belong there.

Paths from the process-name cache can be NT device paths (`\Device\HarddiskVolume4\...`) rather than drive-letter paths, which `WinVerifyTrust`/`CreateFile` can't open directly — these are rewritten with the `\\?\GLOBALROOT` prefix first, the documented way to make an NT-namespace path Win32-openable.

#### Catalog-Signed Files (Most of Windows Itself)

Most Windows system binaries — `notepad.exe` included — aren't Authenticode-*embedded*-signed; their signature lives in a separate `.cat` catalog file, registered against the binary's hash, not inside the PE itself. A plain `WinVerifyTrust(WTD_CHOICE_FILE)` check can't see that at all: it reports `TRUST_E_NOSIGNATURE` for a `notepad.exe` that `Get-AuthenticodeSignature` correctly shows as validly, catalog-signed. This was caught empirically while testing this feature — a real `notepad.exe` showed `unsigned/invalid` against a file that was, in fact, properly signed.

So `check_authenticode_signature()` only treats `TRUST_E_NOSIGNATURE` specifically as "try the catalog path instead" (any other failure — a broken chain, a tampered file — stays `unsigned/invalid`, since that's a different, real answer): it hashes the file with `CryptCATAdminCalcHashFromFileHandle2` and looks the hash up against the system's catalog database with `CryptCATAdminEnumCatalogFromHash`, then verifies against the matching catalog with a second `WinVerifyTrust(WTD_CHOICE_CATALOG)` call. This has to use the **SHA-256** variant of the catalog-hashing API (`CryptCATAdminAcquireContext2`/`...CalcHashFromFileHandle2`, requesting `L"SHA256"`), not the legacy SHA-1 `CryptCATAdminCalcHashFromFileHandle` — also confirmed empirically: the SHA-1 hash still resolves to *a* matching catalog (Windows keeps a legacy lookup index), but the follow-up digest check against it then fails with `TRUST_E_BAD_DIGEST`, because modern catalogs are actually keyed by SHA-256.

`get_signer_name()` only extracts a signer name from an *embedded* PKCS#7 blob, so calling it against `file_path` for a catalog-signed file just fails the same way the primary check did — there's genuinely nothing embedded in `notepad.exe` itself to find. The fix isn't a different extraction method, though: the `.cat` catalog file itself turns out to *be* embedded-Authenticode-signed (confirmed empirically — `Get-AuthenticodeSignature` on notepad.exe's own catalog reports `SignatureType: Authenticode`, not `Catalog`), so `verify_via_catalog()` returns the catalog's path on success, and `check_authenticode_signature()` calls the same, unmodified `get_signer_name()` against *that* path instead. `notepad.exe` now correctly shows `valid (Microsoft Windows)` rather than `valid (signer unavailable)`.

These catalog APIs (`CryptCATAdminAcquireContext2`, `...FromFileHandle2`) require `NTDDI_VERSION >= NTDDI_WIN8` in the SDK headers, but this project's `.vcxproj` targets `_WIN32_WINNT=0x601` (Windows 7) across every example it builds. Rather than raise that project-wide (affecting every other example's minimum OS version), `NTDDI_VERSION` is bumped with `#undef`/`#define` immediately before `#include <mscat.h>` — scoped to just that one header, in just this one translation unit.

#### Signature-Corroborated Same-Image Suppression

Same-image alone (above) is deliberately never suppressed, because it's spoofable. But same-image *plus* a valid, matching Authenticode signature on both sides is materially different evidence: forging that combination requires an actual compromised code-signing certificate, not just copying a trusted binary's path. When `-s`/`--verify-signatures` is enabled and both conditions hold, the event is promoted to the same treatment as the two structural filters — suppressed by default, shown under `-v` as:

```
[i] Same-image thread, signer-verified (not injection): caller PID=... target PID=...
```

This only fires with `-s` enabled — without signature evidence, is_same_image stays at its normal always-shown `[?]` label. It's still not a claim that the specific thread being created is benign, only that the two binaries on disk are what they claim to be and match; a legitimately-signed, unmodified binary can still be used as a launcher in other ways signature verification can't see. It's meant to remove a very common, well-understood category of noise (an application's own multi-process architecture, self-corroborated by matching signatures) — not to certify the event.

### Cross-Component Same-Publisher Labeling

A vendor's own components routinely create threads in each other — an HP background service creating a thread in a sibling HP host process (`HPSystemEventUtilityBackground.exe` → `HPSystemEventUtilityHost.exe`, both `HP Inc.`-signed) is exactly the same shape as the earlier Adobe/Visual Studio examples, just now with signature evidence available via `-s`.

This is deliberately kept in the *labeled, not suppressed* tier — `[?] Cross-component same-publisher thread (different binaries, matching signer; not auto-verified)` — rather than promoted to suppression the way same-image is. The reason is the gap between "same file" and "same publisher": a publisher can ship many binaries, some old, some new, some more trustworthy than others. A vulnerable or compromised older component signed by the same publisher being abused to reach into a current one would look identical by this signal alone — that's a meaningfully weaker guarantee than "the exact same file on both sides," so it gets the weaker (visible-but-flagged) treatment, not the stronger (suppressed) one.

### svchost.exe Service-Group Context

`svchost.exe` hosts dozens of unrelated Windows services behind one process name — "caller PID=X (svchost.exe)" alone tells an analyst nothing about *which* service, and some of them have jobs that inherently involve creating threads in arbitrary third-party executables: Task Scheduler triggering a vendor's scheduled maintenance task, or the Windows Update Orchestrator (`UsoSvc`) managing an update worker. Seeing `svchost.exe → NvTmMon.exe` (NVIDIA) or `svchost.exe → MoUsoCoreWorker.exe` with `Signer match: no` isn't suspicious in either case — it's Task Scheduler and Windows Update doing their normal job, confirmed on a live machine: `sc.exe qc Schedule` and `sc.exe qc UsoSvc` both show `-k netsvcs -p`, and NVIDIA's own telemetry monitor is registered as a Scheduled Task (`Get-ScheduledTask`) that launches under exactly that group.

The service group is sitting right there on svchost's own `CommandLine` (`-k <group>`), so `extract_svchost_service_group()` reads it and prints `Caller svchost service group: -k netsvcs` alongside the event — always on, no flag needed, since it's a cheap string search over already-cached data, not a new capability with a latency cost like signature verification.

This is deliberately **display-only, not a filter** — unlike `csrss.exe` (a single, narrow, well-known role; see "Initial-Thread Filtering" above), `svchost.exe` hosts wildly different services with wildly different behavior, and it's also one of the most commonly masqueraded process names in real-world malware precisely because it's so common and usually ignored. A blanket "svchost.exe is safe" rule would be a much larger blind spot than the equivalent csrss.exe one. Surfacing the service group gives a human the context to judge quickly, without the tool claiming a certainty it doesn't have.

### Trace Buffer Tuning & EventsLost Tracking

By default, `StartTrace()` leaves `BufferSize`/`MinimumBuffers`/`MaximumBuffers`/`FlushTimer` at `0`, which tells ETW to auto-size buffers based on CPU count. That's a reasonable baseline but leaves no headroom for bursts — and this session watches process, thread, *and* image-load activity system-wide on one logger, so a burst of process churn (a build running, several processes launching/exiting close together) is exactly the kind of load that can overrun auto-sized buffers. When that happens, ETW silently drops events — your own callbacks (`handle_process_event`, `handle_thread_event`, `handle_image_load_event`) never even see the ones that were dropped, so there's no way to notice from inside the tool's own event handling.

Two changes address this:

1. **Tuned properties** — `build_tuned_trace_properties()` sets `BufferSize = 128` (KB), `MinimumBuffers = 4 * CPU count`, `MaximumBuffers = 8 * CPU count`, and `FlushTimer = 1` (second), applied via `trace.set_trace_properties(&tuned_properties)` before any provider is enabled or the trace is started (both are hard requirements of that API). Buffer counts scale with `GetSystemInfo()`'s processor count rather than a single hardcoded value, so the tuning stays reasonable across machines.

2. **EventsLost tracking** — a background thread calls `trace.query_stats()` (which asks ETW directly for the session's live counters via `ControlTrace(..., EVENT_TRACE_CONTROL_QUERY)`) every 30 seconds and logs events handled/lost and buffer counts. If `EventsLost` increased since the last check, it's flagged with a `[!] WARNING` line telling you buffers are being overrun — the only way this tool can tell you it's not seeing everything.

```
[stats] events handled=48213  events lost=0  buffers written=112  buffers lost=0  buffers free=18/32
```

If you see `events lost` climbing, raise `BufferSize`/`MinimumBuffers` further in `build_tuned_trace_properties()`.

## Requirements

- **Windows 10 or later** (any edition)
- **Administrator privileges** (kernel-level ETW tracing requires elevation)
- **x64 or ARM64 build** (32-bit Windows is not supported)
- **Visual Studio 2019+** (for building)
- **Krabs library** (included in the repository)

## Building

### Using Visual Studio

1. Open `krabs.sln` in the repository root
2. Select "NativeExamples" project
3. Build → Build Solution (or Ctrl+Shift+B)
4. Output binary: `<repo-root>/examples/NativeExamples/x64/Debug/NativeExamples.exe` (or Release)

### From Command Line (MSVC)

```bash
cd <repo-root>/examples/NativeExamples
cl.exe /EHsc /I..\..\krabs remote_thread_detect.cpp kernel32.lib advapi32.lib
```

### Integration into Main.cpp

The tool is built as part of the NativeExamples project. To run it instead of other examples, edit `main.cpp`:

```cpp
int main(void)
{
    // Uncomment the remote thread detection example:
    remote_thread_detect::start();  // <-- add this line
    
    return 0;
}
```

Add the function signature to `examples.h`:

```cpp
namespace remote_thread_detect {
    void start();
}
```

## Usage

### Basic Monitoring

```bash
# Run as Administrator
remote_thread_detect.exe
```

**Output:**
```
Monitoring for remote thread creation... (Ctrl+C to stop)
[!] Remote thread created: caller PID=1234 (C:\path\to\caller.exe)  target PID=5678 (C:\path\to\target.exe)
    Win32StartAddr -> C:\Windows\System32\kernel32.dll+0x42990
      ProcessId = 5678
      TThreadId = 9012
      ... (all event properties)
```

### Verbose Mode (Include Filtered Categories)

```bash
# Include remote threads originating from System (PID 4), a process's own
# initial thread, and kernel-mode pico-process targets (e.g. MemCompression)
# Useful for auditing what's being filtered, but generates a lot more noise
remote_thread_detect.exe -v
# or
remote_thread_detect.exe --verbose
```

In verbose mode, filtered events are still distinguished from real candidates by their label:

```
[!] Remote thread created: ...                                       <- candidate, always shown
[?] Same-image parent->child thread (...): ...                       <- always shown, weak signal
[?] Cross-component same-publisher thread (...): ...                 <- always shown, weak signal, needs -s
[i] Initial thread of newly created process (not injection): ...     <- verbose-only
[i] Kernel-mode system thread, not a usermode injection target: ...  <- verbose-only
[i] Same-image thread, signer-verified (not injection): ...          <- verbose-only, needs -s
```

### Signature Verification Mode

```bash
# Check Authenticode signatures (and signer match) for caller/target on
# every event that's still shown after filtering. Adds latency per event
# (see "Optional Authenticode Verification" above) -- off by default.
remote_thread_detect.exe -s
# or
remote_thread_detect.exe --verify-signatures

# Combine with -v to also see it on filtered categories
remote_thread_detect.exe -v -s
```

### Stopping the Trace

Press **Ctrl+C** to cleanly stop monitoring. This properly tears down the ETW session, preventing orphaned sessions that would interfere with subsequent runs.

## Output Format

### Event Header

```
[!] Remote thread created: caller PID=<pid> (<caller_path>)  target PID=<pid> (<target_path>)
```

### Win32StartAddr Resolution

```
Win32StartAddr -> <resolution>
```

Where `<resolution>` is one of:

| Resolution | Meaning |
|-----------|---------|
| `path\module.dll+0x1234` | Thread starts in a known loaded module (normal/legitimate) |
| `<UNBACKED -- not inside any known loaded module (possible injected code)>` | Address is in private/unmapped memory (suspicious — suggests injected code or shellcode) |
| `<incomplete module info for this PID -- main executable not yet recorded by image rundown>` | Module cache not yet populated (usually during initial process startup); wait and re-check |

### Event Payload

All ETW event properties are displayed as name=value pairs:

```
      ProcessId = 5678
      TThreadId = 9012
      StackBase = 0xfffff580...
      Win32StartAddr = 0x7ff6357e8c70
      ... (all properties, type-aware formatted)
```

## Testing with the Python Injection Script

The repository includes `inject_test.py` — a benign CreateRemoteThread PoC that's perfect for validating detection:

### Setup

1. **Start the detector** (in Administrator PowerShell/Command Prompt):
   ```bash
   cd <repo-root>/examples/NativeExamples/x64/Debug
   NativeExamples.exe
   ```

2. **In another terminal**, run the injection test:
   ```bash
   cd <repo-root>/examples
   python inject_test.py
   ```

### Test Scenario 1: LoadLibraryA Injection (Default)

```bash
python inject_test.py
```

**Expected Output in Detector:**
```
[!] Remote thread created: caller PID=39668 (python)  target PID=33436 (C:\Windows\System32\notepad.exe)
    Win32StartAddr -> C:\Windows\System32\kernel32.dll+0x42990
```

The thread starts in `kernel32.dll` — a legitimate module. This is a safe injection technique (remoting a function call into another process's already-loaded code).

### Test Scenario 2: Shellcode Injection

```bash
python inject_test.py --mode shellcode
```

**Expected Output in Detector:**
```
[!] Remote thread created: caller PID=39668 (python)  target PID=33436 (C:\Windows\System32\notepad.exe)
    Win32StartAddr -> <UNBACKED -- not inside any known loaded module (possible injected code)>
```

The thread starts in private memory — the "UNBACKED" marker signals injected code.

### Script Options

```
python inject_test.py --help
```

| Option | Default | Purpose |
|--------|---------|---------|
| `--mode {loadlibrary, shellcode}` | `loadlibrary` | Injection technique to use |
| `--pid <PID>` | (none) | Target an existing process instead of spawning notepad |
| `--target-exe <path>` | `C:\Windows\System32\notepad.exe` | Executable to spawn |
| `--dll <path>` | `C:\Windows\System32\version.dll` | DLL to load in loadlibrary mode |

## Known Limitations

### 1. Cross-CPU Delivery Races

ETW only guarantees ordering within a single CPU's buffer. Events from two providers on different CPUs may arrive interleaved. The 300ms grace period in `kResolveDelay` is a pragmatic trade-off — increase it if seeing "incomplete module info" errors in your environment.

### 2. Module Cache Unbounded Growth

The process name cache does *not* evict entries when a process exits (see line 186 in the source). This keeps the cache bounded for long-running deployments but means PIDs that are never reused will accumulate. Uncomment the `erase()` call if memory growth is a concern; the trade-off is a small race window where a late remote-thread event for a just-exited process might show as `<unknown>`.

### 3. Schema Variations Across Windows Versions

ETW schemas for image-load and thread events can vary slightly across Windows versions. The code is defensive (probes multiple type candidates, logs diagnostics), but if you see repeated `[diag]` messages for a field type mismatch, inspect the payload dump and adjust field-type guesses in `try_parse_as_address()`.

### 4. 32-bit Processes on 64-bit Windows

This tool is built as 64-bit only. It can observe 32-bit target processes (WoW64), but the `Win32StartAddr` values will be in the 32-bit address space of the WoW64 emulation layer. Module resolution should still work but may be less reliable.

### 5. Kernel Mode Injection

This tool monitors *user-mode* thread creation via `CreateRemoteThread()` and kernel event tracing. It does *not* detect:
- Direct kernel-mode code injection
- Memory patching without remote thread creation
- Techniques that bypass ETW entirely
- `QueueUserAPC` injection or thread hijacking (`SetThreadContext`) — neither creates a new thread, so no thread-create event exists to catch

### 6. Filtering Heuristics Are Timing-Based, Not Guaranteed

The initial-thread filter (see "Initial-Thread Filtering" above) relies on a 500ms window between a process's creation and its first thread's creation. Under extreme system load this window could theoretically be exceeded, or a genuinely malicious parent could deliberately inject into its own child within that window to blend in — the filter reduces a very common false positive, it isn't a security boundary. Similarly, the kernel-mode-target filter trusts that `UserStackBase`/`TebBase` being zero reliably means "no usermode context"; this holds for known pico-processes today but isn't a documented Microsoft guarantee for all possible future process types.

## Troubleshooting

### "Orphaned Session" Error on Startup

**Symptom:** Running the tool twice in quick succession, or without Ctrl+C:

```
[ETW Session Error] RemoteThreadTrace session already exists...
```

**Cause:** A previous run was terminated without calling `trace.stop()`, leaving the ETW session running system-wide.

**Fix:**
```bash
# Forcefully stop all ETW sessions (requires Administrator)
logman stop RemoteThreadTrace
```

Or simply press Ctrl+C in the detector window to trigger the cleanup handler.

### Missing Module Information

**Symptom:** Events show `<incomplete module info for this PID...>` or don't show Win32StartAddr at all.

**Possible Causes:**
- **Image-load events not arriving:** Ensure the image_load_provider is enabled (check source line 607)
- **Fast process startup:** Processes that start and create remote threads very quickly may outrun the 300ms grace period; increase `kResolveDelay` if needed
- **Newly spawned targets:** The target process's own module information can take time to populate; see "Main-Image Confirmation" above — this resolves itself given a little more time
- **The same PID shows this on every event, and never resolves:** The target is very likely a kernel-mode minimal/pico process (`MemCompression`, `Secure System`, `Registry`) that will never load a usermode image, so the module cache can never be populated for it. Run with `-v` to confirm — a filtered kernel-mode-target event will show `TebBase = 0` and `UserStackBase = 0` in its payload dump.

### Detector Consuming High CPU

**Cause:** The resolver background thread is waiting in a tight loop.

**Fix:** Ensure `g_pending_cv.wait()` calls are properly synchronized; this is a sign of a race condition in the locking logic. File an issue with a minimal reproduction.

## Architecture Decisions

### Why Deferred Resolution?

Synchronous resolution in `handle_thread_event()` would result in almost every new target process showing "incomplete module info" due to the cross-CPU delivery race (see "Deferred Resolution Pattern" above). Deferring with a grace period trades a small fixed latency (300ms) for reliable, deterministic results.

### Why Not Use a Name-to-Index Map?

Early versions used a static hash map for property name lookup (ETW field names → property indices). Performance testing showed that for typical events with < ~12 properties, a hinted linear scan (the current approach) is faster due to cache locality and lower memory overhead.

### Why Not Evict Exited Process Names?

Evicting on process exit would close a small race window: if a remote-thread event for a just-exited process arrives in the microsecond window between the Exit event and the cache eviction, the process name would be lost. Keeping the cache around (and only filling PID-reuse correctly) is simpler and more robust. The memory cost is negligible on typical machines.

### Why Filter by Timing + ParentId Instead of Just ParentId?

A parent creating threads in its own child *is* a valid signal for something worth flagging — process hollowing does exactly this. If the filter matched on ParentId alone, it would silently hide that. Requiring the thread-create event to land within 500ms of the process-create event narrows the filter to specifically "the process being born," while still surfacing a parent reaching into its own child later.

### Why Detect Kernel-Mode Targets by Field Values Instead of Process Name?

Matching on the name `"MemCompression"` would be brittle (Windows has added pico-processes over releases, and names aren't a stable contract) and wouldn't generalize to a similar process introduced in a future Windows version. `UserStackBase`/`TebBase` being zero is a structural property of how the kernel creates a thread with no usermode context — it's the actual reason resolution is meaningless here, not just a correlated symptom.

### Why Isn't Same-Image a Filter, Like the Other Two?

The initial-thread and kernel-mode-target filters key on facts the kernel guarantees are true — an attacker can't fake a ParentId+timing match or a zero TEB, because those are consequences of how the OS actually creates those specific threads. "Caller and target run the same executable" has no such guarantee behind it; it's just a path string, and an attacker can trivially spawn a copy of any trusted binary as a decoy child. Filtering on it would create a blind spot exactly where masquerading-via-trusted-binary techniques would want one. Labeling it instead keeps it visible while still telling you it's a common, lower-priority-to-review pattern.

## Contributing

Contributions welcome! Common enhancement ideas:

- Support for 32-bit build variants
- Persistent logging to CSV/JSON for post-analysis
- GUI dashboard for real-time visualization
- Integration with SIEM platforms
- ML-based heuristics for suspicious injection patterns

## License

This code is part of the Krabs repository and is licensed under the MIT License. See the repository root for details.

## References

- [Event Tracing for Windows (ETW)](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)
- [Krabs Library Documentation](https://github.com/microsoft/krabs-etw)
- [Process Thread Creation Event](https://docs.microsoft.com/en-us/windows/win32/etw/proc_thread_create)
- [Image Load Event](https://docs.microsoft.com/en-us/windows/win32/etw/image_load)
- [CreateRemoteThread API](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)

## FAQ

### Q: Can this detect DLL injection?
**A:** If the DLL is loaded via `LoadLibrary()` (inside a remote thread), yes — the thread would show as starting in `kernel32!LoadLibraryA`. If the DLL is injected directly (memory patching without a remote thread), no — this tool is thread-focused.

### Q: Does this require the target process to be running?
**A:** Yes. Remote threads are created against a live process handle. Once created, they appear as regular threads in the target process.

### Q: Why does the Python injection script spawn notepad?
**A:** Notepad is guaranteed to be present on all Windows machines and is a safe, non-critical process to test against. You can pass `--pid` to target an existing process instead.

### Q: Can I filter events in the tool?
**A:** Currently, filtering is minimal (only System PID 4 can be excluded with `--verbose`). For post-processing, redirect output to a file and filter with grep/awk, or modify `handle_thread_event()` to add custom predicates.

### Q: Is this a replacement for Windows Defender / antivirus detection?
**A:** No. This is a *monitoring* and *visibility* tool — useful for research, incident response, and building detection rules. Production EDR/antivirus solutions use multiple detection techniques and have extensive tuning.
