// remote_thread_detect.cpp
//
// Detects cross-process (remote) thread creation via ETW, and resolves
// both the caller and target PIDs to full executable paths (falling back
// to the bare image name if a path can't be recovered) using a
// process-table cache built from process_provider Start/DCStart events.
// Also resolves the new thread's Win32StartAddr against a per-process
// loaded-module cache (image_load_provider), so it's immediately visible
// whether the thread starts inside a known DLL/EXE or in unbacked memory.
//
// Requires Administrator privileges (kernel-level ETW tracing).
// Target x64 or ARM64.

#include <iostream>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <deque>
#include <algorithm>
#include <cctype>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <chrono>
#include <string>
#include <optional>
#include <cstring>
#include "..\..\krabs\krabs.hpp"
#include <psapi.h>
#include <wincrypt.h>
#include <softpub.h> 
#include <wintrust.h>
// The project targets _WIN32_WINNT=0x601 (Windows 7) for broad example
// compatibility, but CryptCATAdminAcquireContext2/...FromFileHandle2 --
// needed for the SHA-256 catalog-signature fallback below -- are gated in
// the SDK header behind NTDDI_VERSION >= NTDDI_WIN8. Raising it just for
// this include, in this one translation unit, avoids changing the
// project-wide Windows 7 target for every other example in the same
// vcxproj.
#undef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN8
#include <mscat.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

// Forward declaration -- defined further down; reused here as a diagnostic
// dump when a provider's expected property names don't match reality on a
// given OS build (classic MOF/WMI schemas aren't guaranteed identical
// across Windows versions).
void print_event_payload(krabs::parser &parser);

// Parses a property while fully swallowing any exception, including
// krabs::type_mismatch_assert -- which krabs::parser::try_parse
// deliberately re-throws (rather than swallowing) in debug builds, so
// mismatches show up loudly during normal development. That's exactly what
// we don't want here: we're intentionally probing a field under several
// candidate types, so a wrong guess needs to be a normal, silent case.
template <typename T>
bool safe_try_parse(krabs::parser &parser, std::wstring_view name, T &out)
{
    try {
        out = parser.parse<T>(name);
        return true;
    }
    catch (...) {
        return false;
    }
}

// Address-sized fields (base addresses, sizes) show up under different TDH
// types across OS builds/providers -- try POINTER first, then plain
// 64/32-bit integers.
bool try_parse_as_address(krabs::parser &parser, std::wstring_view name, uint64_t &out)
{
    krabs::pointer p;
    if (safe_try_parse(parser, name, p)) { out = p.address; return true; }

    uint64_t v64 = 0;
    if (safe_try_parse(parser, name, v64)) { out = v64; return true; }

    uint32_t v32 = 0;
    if (safe_try_parse(parser, name, v32)) { out = v32; return true; }

    return false;
}

// --- Process name cache, keyed by PID -------------------------------------
//
// Built from process_provider events. Overwritten on every Start/DCStart,
// so PID reuse (a new process reusing an old PID) self-corrects on the
// next Start event -- but entries for exited processes whose PID is never
// reused will remain until evicted. See the note on End/DCEnd handling
// below for the memory-growth tradeoff this implies.

std::unordered_map<uint32_t, std::string> g_process_names;

// Captures each process's ParentId and creation timestamp (from its Start/
// DCStart event) so a remote-thread event can be checked against "is this
// just the new process's own initial thread, created by its parent as part
// of normal CreateProcess()?" -- see is_initial_process_thread() below.
struct process_start_info {
    uint32_t parent_id;
    int64_t start_time; // FILETIME-style 100ns ticks, from EVENT_HEADER.TimeStamp
};

std::unordered_map<uint32_t, process_start_info> g_process_start_info;

// Raw CommandLine text, kept separately from g_process_names (which holds
// just the resolved display path) so svchost.exe's "-k <service group>"
// argument is still available later -- see extract_svchost_service_group().
std::unordered_map<uint32_t, std::string> g_process_command_lines;

// Guards all three caches above -- they're always populated together from
// the same process Start/DCStart event.
std::mutex g_process_names_mutex;

// --- Command-line options --------------------------------------------------
//
// -v / --verbose: also report remote threads originating from the System
// process (PID 4); remote-thread events that are actually just a process's
// own initial thread being created by its parent (see
// is_initial_process_thread()); and threads created inside kernel-mode
// minimal/pico processes like MemCompression (see is_kernel_mode_target()).
// All three are common and suppressed by default to reduce noise.

bool g_verbose = false;

// -s / --verify-signatures: check the Authenticode signature of the caller
// and target executables (and whether they share a signer) for every event
// still shown after filtering. Off by default -- WinVerifyTrust does real
// cryptographic and cert-chain work per file, which is real added latency
// per event. It's run from the resolver thread (never the ETW callback
// thread) for exactly that reason -- see the "Trace session tuning" section
// on why blocking the callback thread risks EventsLost.
bool g_verify_signatures = false;

// Multiple threads write multi-line blocks to std::cout independently (the
// ETW callback thread's diagnostic dumps, the resolver thread's per-event
// output, the stats thread's periodic line) -- each individual `<<` call
// is thread-safe, but the *sequence* composing one logical block is not,
// so without this those blocks can (and, confirmed live, does) interleave
// mid-line -- e.g. a "[stats] ..." line splicing itself into the middle of
// a "Win32StartAddr -> ..." line. Guards a whole block at a time via RAII,
// not individual writes.
std::mutex g_cout_mutex;

constexpr uint32_t SYSTEM_PID = 4;

// --- Debug privilege -----------------------------------------------------
//
// Administrator elevation (already required for kernel ETW tracing) does
// NOT by itself grant OpenProcess() access to every process -- a handful of
// protected/cross-session system processes (wininit.exe, winlogon.exe, a
// non-interactive-session csrss.exe) still return ERROR_ACCESS_DENIED. An
// elevated token *holds* SeDebugPrivilege, but it's disabled by default;
// it has to be explicitly enabled, the same way Task Manager/Process
// Explorer/every other process-inspection tool does at startup, before
// populate_modules_from_live_snapshot()'s OpenProcess() calls can reach
// those processes.
bool enable_debug_privilege()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
        return false;
    }

    LUID luid = {};
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES privileges = {};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL adjusted = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
    DWORD adjust_error = GetLastError();
    CloseHandle(token);

    // AdjustTokenPrivileges can report success (nonzero return) while still
    // failing to enable the specific privilege requested -- checking
    // ERROR_NOT_ALL_ASSIGNED is the documented way to catch that case.
    return adjusted && adjust_error != ERROR_NOT_ALL_ASSIGNED;
}

// --- Clean shutdown ----------------------------------------------------
//
// The kernel session name ("RemoteThreadTrace") is global to the machine.
// trace.start() blocks the main thread inside ProcessTrace(); the default
// Ctrl+C behavior terminates the process immediately, without ever
// reaching trace.stop() -- which leaves the session running system-wide
// with whatever flags this run happened to enable. The next run then
// silently attaches to that stale session instead of creating a fresh one,
// so image_load (or any provider added later) can appear to just not
// work. Handling the console control events and calling trace.stop()
// explicitly (from the handler's own OS-provided thread) lets
// ProcessTrace() return normally and the session tear down properly.

krabs::kernel_trace *g_trace = nullptr;

BOOL WINAPI console_ctrl_handler(DWORD ctrl_type)
{
    switch (ctrl_type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        if (g_trace != nullptr) {
            std::cout << std::endl << "Stopping trace..." << std::endl;
            g_trace->stop();
        }
        return TRUE; // handled -- suppress the default terminate-immediately behavior
    default:
        return FALSE;
    }
}

// Pulls the executable path out of a process's CommandLine (quoted or not).
// Falls back to an empty string if CommandLine wasn't present/parseable,
// in which case the caller should fall back to the bare image name.
std::string extract_executable_path(const std::wstring &command_line)
{
    if (command_line.empty()) {
        return std::string();
    }

    std::wstring path;
    if (command_line.front() == L'"') {
        size_t end_quote = command_line.find(L'"', 1);
        path = command_line.substr(1, (end_quote == std::wstring::npos) ? std::wstring::npos : end_quote - 1);
    }
    else {
        size_t space = command_line.find(L' ');
        path = command_line.substr(0, space);
    }

    return std::string(path.begin(), path.end());
}

// Attempts to resolve a process's full executable path via Windows API.
// Falls back gracefully if the process no longer exists or can't be opened.
std::string resolve_process_path(uint32_t pid)
{
    HANDLE h_proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h_proc) {
        return "";
    }

    wchar_t path_buf[MAX_PATH] = { 0 };
    DWORD path_len = sizeof(path_buf) / sizeof(path_buf[0]);

    std::string result;
    if (GetProcessImageFileNameW(h_proc, path_buf, path_len)) {
        // Convert NT device path to DOS drive path if needed
        // e.g., "\Device\HarddiskVolume4\Windows\System32\notepad.exe" -> "C:\Windows\System32\notepad.exe"
        std::wstring nt_path(path_buf);

        // For simplicity, just use the path as-is (NT or DOS format both work for display)
        // If you want to convert, that requires a separate lookup table
        result = std::string(nt_path.begin(), nt_path.end());
    }

    CloseHandle(h_proc);
    return result;
}

void handle_process_event(const EVENT_RECORD &record, const krabs::trace_context &trace_context)
{
    krabs::schema schema(record, trace_context.schema_locator);
    int opcode = schema.event_opcode();

    if (opcode < 1 || opcode > 4) {
        return;
    }

    krabs::parser parser(schema);
    std::string image_name;
    std::wstring command_line;
    uint32_t pid = 0;

    if (!parser.try_parse(L"ImageFileName", image_name) ||
        !parser.try_parse(L"ProcessId", pid)) {
        return;
    }

    // Best-effort: absence just means the initial-thread correlation below
    // won't fire for this process, not that the event is unusable.
    uint32_t parent_pid = 0;
    parser.try_parse(L"ParentId", parent_pid);

    // CommandLine isn't guaranteed to be present on every event, and even
    // when it is, it's the path as invoked -- not a canonicalized one -- so
    // treat it as best-effort and fall back to the bare image name.
    parser.try_parse(L"CommandLine", command_line);
    std::string path = extract_executable_path(command_line);

    // If we only got a bare name, try to resolve the full path via Windows API
    if (path.empty() || path.find('\\') == std::string::npos) {
        std::string resolved = resolve_process_path(pid);
        if (!resolved.empty()) {
            path = resolved;
        }
    }

    const std::string &display_name = !path.empty() ? path : image_name;

    std::lock_guard<std::mutex> lock(g_process_names_mutex);

    if (opcode == 1 || opcode == 3) { // Start, DCStart
        g_process_names[pid] = display_name;
        g_process_start_info[pid] = { parent_pid, record.EventHeader.TimeStamp.QuadPart };
        g_process_command_lines[pid] = std::string(command_line.begin(), command_line.end());
    }
    else { // End, DCEnd (opcode == 2 || opcode == 4)
        // Choice point: evicting here keeps the cache bounded for a
        // long-running trace, at the cost of losing the name if a
        // remote-thread event referencing this PID arrives in a very
        // tight race right after exit. Left commented out -- uncomment
        // if unbounded memory growth over a long deployment is the
        // bigger concern for your use case.
        //
        // g_process_names.erase(pid);
    }
}

std::string lookup_process_name(uint32_t pid)
{
    std::lock_guard<std::mutex> lock(g_process_names_mutex);
    auto it = g_process_names.find(pid);
    return (it != g_process_names.end()) ? it->second : "<unknown>";
}

std::string lookup_process_command_line(uint32_t pid)
{
    std::lock_guard<std::mutex> lock(g_process_names_mutex);
    auto it = g_process_command_lines.find(pid);
    return (it != g_process_command_lines.end()) ? it->second : "";
}

// svchost.exe hosts dozens of unrelated Windows services behind one opaque
// process name -- by itself, "caller PID=X (svchost.exe)" tells an analyst
// nothing about which one, and several genuinely benign, well-known
// services (Task Scheduler, the Windows Update Orchestrator) legitimately
// create threads in arbitrary third-party executables as their normal job
// (launching/managing scheduled tasks, update workers). The service group
// (-k <group>) is sitting right there on svchost's own command line and
// immediately narrows that down for a human -- confirmed on a live machine
// that both Task Scheduler ("Schedule") and the Update Orchestrator
// ("UsoSvc") run under "-k netsvcs -p" (`sc.exe qc <name>`), which is
// exactly the group that showed up for an NVIDIA scheduled-task worker and
// a Windows Update worker in unrelated remote-thread events.
//
// This is display-only, not a filter, and deliberately so: unlike
// csrss.exe (a single, narrow, well-known role -- see
// is_initial_process_thread()), svchost hosts wildly different services
// with wildly different behavior, so "which service group" is surfaced as
// context for a human to judge, not something safe to auto-suppress on.
std::optional<std::string> extract_svchost_service_group(const std::string &command_line)
{
    size_t k_pos = command_line.find("-k ");
    if (k_pos == std::string::npos) {
        return std::nullopt;
    }

    size_t group_start = k_pos + 3;
    size_t group_end = command_line.find(' ', group_start);
    std::string group = command_line.substr(group_start,
        (group_end == std::string::npos) ? std::string::npos : group_end - group_start);

    return group.empty() ? std::nullopt : std::optional<std::string>(group);
}

// Every process's initial thread is created by its *parent* -- as part of
// NtCreateUserProcess, the parent's own thread creates the new process object
// and its first thread before the child ever runs a single instruction. The
// resulting kernel ThreadStart event therefore always has
// EventHeader.ProcessId (the caller) pointing at the parent and the event's
// own ProcessId property (the target) pointing at the brand-new child --
// indistinguishable, by PID pattern alone, from genuine remote-thread
// injection. This is the single largest source of false positives for a
// naive "caller PID != target PID" rule: it fires on every process launch.
//
// The two events aren't merely correlated by PID, though -- they're the same
// kernel operation, so the process's Start/DCStart event and this thread's
// Start event land within microseconds of each other. Real injection into an
// already-running child (e.g. process hollowing) happens measurably later,
// once the child has been alive long enough to be a useful target. Requiring
// both an exact ParentId match *and* a tight time window (rather than either
// alone) is what tells "this is the process being born" apart from "the
// parent reached into its child after the fact".
constexpr int64_t kInitialThreadWindow100ns = 500 * 10'000; // 500ms, in 100ns FILETIME ticks

// Broken out from a plain bool so a "not the initial thread" verdict can be
// explained, not just asserted -- see its use under -v in print_pending_event.
// Distinguishing "target's Process-Start event isn't in the cache at all"
// from "it's there, but ParentId/timing didn't match" is exactly the
// question needed to tell apart two very different situations that would
// otherwise look identical from the outside: the cross-provider race this
// check already lost to once (see "Bug: This Check Was Racing..." in the
// docs) versus a target process that's just genuinely receiving a *second*
// thread sometime after it was created, which is a structurally different
// (and real) remote-thread-into-an-existing-process event, however likely
// benign it turns out to be otherwise.
struct initial_thread_diagnosis {
    bool found_process_start_info;
    uint32_t recorded_parent_id; // meaningful only if found_process_start_info
    int64_t delta_100ns;         // meaningful only if found_process_start_info
    bool is_initial_thread;
};

initial_thread_diagnosis diagnose_initial_process_thread(uint32_t target_pid, uint32_t caller_pid, int64_t thread_event_time)
{
    initial_thread_diagnosis result = {};

    std::lock_guard<std::mutex> lock(g_process_names_mutex);
    auto it = g_process_start_info.find(target_pid);
    if (it == g_process_start_info.end()) {
        return result;
    }

    result.found_process_start_info = true;
    result.recorded_parent_id = it->second.parent_id;

    int64_t delta = thread_event_time - it->second.start_time;
    if (delta < 0) {
        delta = -delta;
    }
    result.delta_100ns = delta;

    result.is_initial_thread = (it->second.parent_id == caller_pid) && (delta <= kInitialThreadWindow100ns);
    return result;
}

// --- Loaded-module cache, keyed by PID --------------------------------------
//
// Built from image_load_provider Load/DCStart events, so a Win32StartAddr
// can be resolved to "which DLL/EXE is this actually inside of". Entries
// are removed on Unload -- unlike the process-name cache, a stale entry
// here is actively misleading (it would attribute a freshly unmapped
// address range to a module that no longer owns it), so eviction isn't
// optional the way it is for exited-process names.

struct module_info {
    uint64_t base;
    uint64_t size;
    std::string path;
};

std::unordered_map<uint32_t, std::vector<module_info>> g_process_modules;
std::mutex g_process_modules_mutex;

void handle_image_load_event(const EVENT_RECORD &record, const krabs::trace_context &trace_context)
{
    krabs::schema schema(record, trace_context.schema_locator);
    int opcode = schema.event_opcode();

    // Load = 10, Unload = 2, DCStart = 3, DCEnd = 4 (EVENT_TRACE_TYPE_*)
    if (opcode != 10 && opcode != 2 && opcode != 3 && opcode != 4) {
        return;
    }

    krabs::parser parser(schema);

    // Image-load events fire in the loading process's context, so the PID
    // comes straight from the record header -- no need to depend on a
    // ProcessId property that may or may not exist under that name here.
    uint32_t pid = record.EventHeader.ProcessId;

    uint64_t image_base = 0;
    uint64_t image_size = 0;
    std::wstring file_name;

    bool got_base = try_parse_as_address(parser, L"ImageBase", image_base);
    bool got_size = try_parse_as_address(parser, L"ImageSize", image_size);

    // The classic Image event's variable-length name field is documented as
    // "FileName"; fall back to "ImageName" in case a given OS build exposes
    // it under the newer name.
    if (!safe_try_parse(parser, L"FileName", file_name)) {
        safe_try_parse(parser, L"ImageName", file_name);
    }

    // If our field-name/type guesses missed, dump the real payload (just
    // the first handful of times) so the actual names can be read off
    // directly instead of guessed again.
    static std::atomic<int> diagnostic_dumps{ 0 };
    if ((!got_base || !got_size) && diagnostic_dumps.fetch_add(1) < 5) {
        std::lock_guard<std::mutex> cout_lock(g_cout_mutex); // see its comment
        std::cout << "[diag] image event opcode=" << opcode << " pid=" << pid
                  << "  got_base=" << got_base << " got_size=" << got_size << std::endl;
        print_event_payload(parser);
    }

    if (!got_base || !got_size) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_process_modules_mutex);
    auto &modules = g_process_modules[pid];

    if (opcode == 10 || opcode == 3) { // Load, DCStart
        modules.push_back({ image_base, image_size, std::string(file_name.begin(), file_name.end()) });
    }
    else { // Unload, DCEnd
        modules.erase(
            std::remove_if(modules.begin(), modules.end(),
                [&](const module_info &m) { return m.base == image_base; }),
            modules.end());
    }
}

// Resolves an address in target_pid's address space to "module+offset", or
// a diagnostic placeholder if it doesn't fall inside any module we know
// about -- which, for a thread's start address, is the signal that matters:
// legitimate threads start inside a loaded module; injected/shellcode
// threads typically start in private (unbacked) memory.
//
// Returns just the filename component of a path (Windows path separators),
// used to compare a module's path against a process's cached image name
// without caring whether either one is an NT device path
// ("\Device\HarddiskVolume4\...") or a DOS drive path ("C:\...").
std::string path_filename(const std::string &path)
{
    size_t pos = path.find_last_of("\\/");
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

bool iequals(const std::string &a, const std::string &b)
{
    if (a.size() != b.size()) {
        return false;
    }
    return std::equal(a.begin(), a.end(), b.begin(), [](char c1, char c2) {
        return std::tolower(static_cast<unsigned char>(c1)) == std::tolower(static_cast<unsigned char>(c2));
    });
}

// The exact same file can show up in either drive-letter form ("C:\foo\bar.exe",
// from CommandLine parsing) or NT device-path form ("\Device\HarddiskVolume4\foo\bar.exe",
// from resolve_process_path()'s GetProcessImageFileNameW fallback), depending on
// which one happened to resolve it -- caller and target can easily end up in
// different forms even when they're literally the same executable. A plain
// string compare misses that. Stripping whichever volume-identifying prefix
// is present leaves just the volume-relative path, which compares correctly
// regardless of which form either side came from.
std::string strip_volume_prefix(const std::string &path)
{
    if (path.size() >= 2 && path[1] == ':') {
        return path.substr(2); // "C:\foo" -> "\foo"
    }

    const std::string device_prefix = "\\Device\\";
    if (path.rfind(device_prefix, 0) == 0) {
        size_t next_slash = path.find('\\', device_prefix.size());
        if (next_slash != std::string::npos) {
            return path.substr(next_slash); // "\Device\HarddiskVolume4\foo" -> "\foo"
        }
    }

    return path;
}

// Several Win32 file APIs (WinVerifyTrust, LoadLibraryExW) reject NT
// device paths outright ("\Device\HarddiskVolume4\..." -- what
// resolve_process_path()'s GetProcessImageFileNameW fallback produces).
// The \\?\GLOBALROOT prefix is the documented way to make an NT-namespace
// path openable through those Win32 APIs.
std::wstring to_openable_path(const std::string &path)
{
    std::wstring wpath(path.begin(), path.end());
    if (wpath.rfind(L"\\Device\\", 0) == 0) {
        return L"\\\\?\\GLOBALROOT" + wpath;
    }
    return wpath;
}

// --- Export-symbol resolution ------------------------------------------
//
// "module+0xN" (below) tells you which file a thread starts in, but not
// what's there -- an analyst still has to go look up that offset by hand.
// Resolving the nearest preceding named export turns
// "kernel32.dll+0x42990" into "kernel32.dll!LoadLibraryA+0x12", which is
// immediately meaningful: that's the exact shape of the classic
// remote-LoadLibrary injection technique inject_test.py's own
// `loadlibrary` mode demonstrates.
//
// Exports are read directly from the on-disk PE file via
// LOAD_LIBRARY_AS_IMAGE_RESOURCE, which maps it with real RVA-correct
// layout (so the export directory's RVAs line up with the mapped base)
// but runs no code -- no DllMain, no import resolution -- unlike the
// deprecated DONT_RESOLVE_DLL_REFERENCES. This only depends on the
// module's on-disk layout, not on which process it's actually loaded in,
// so it's independent of ASLR: the file's *internal* RVA structure is the
// same everywhere, only its base address differs per-process (and base is
// already handled separately, in resolve_module_address's own base/size
// bookkeeping).

struct exported_symbol {
    DWORD rva;
    std::string name;
};

// Plain-old-data only, deliberately: MSVC (C2712) disallows __try/__except
// in a function that also has local C++ objects needing unwind (like a
// std::vector<std::string>), so the actual pointer-walking of the export
// arrays -- reading RVAs and name strings out of a file that's untrusted
// input we didn't produce -- is isolated in this small function with only
// primitive locals, guarded by SEH against a malformed export directory
// (bad NumberOfNames, a dangling RVA) causing an access violation. The
// loader validates the PE headers themselves before LoadLibraryExW can
// succeed at all, but not the export directory's internal consistency --
// nothing walks that array until something (here, us) actually asks for
// exports.
struct raw_export_symbol {
    DWORD rva;
    char name[256];
};

DWORD collect_exports_raw(BYTE *base, DWORD export_rva, DWORD export_size,
                           const IMAGE_EXPORT_DIRECTORY *exports,
                           raw_export_symbol *out, DWORD max_out)
{
    DWORD count = 0;
    __try {
        auto *functions = reinterpret_cast<const DWORD *>(base + exports->AddressOfFunctions);
        auto *names = reinterpret_cast<const DWORD *>(base + exports->AddressOfNames);
        auto *ordinals = reinterpret_cast<const WORD *>(base + exports->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exports->NumberOfNames && count < max_out; i++) {
            WORD func_index = ordinals[i];
            if (func_index >= exports->NumberOfFunctions) {
                continue;
            }

            DWORD func_rva = functions[func_index];
            if (func_rva == 0) {
                continue;
            }

            // A forwarder's "RVA" actually points into the export
            // directory itself (a string like "NTDLL.RtlAllocateHeap"),
            // not real code -- not a landmark we can report an offset
            // from, so skip it.
            if (func_rva >= export_rva && func_rva < export_rva + export_size) {
                continue;
            }

            const char *name_ptr = reinterpret_cast<const char *>(base + names[i]);
            out[count].rva = func_rva;
            strncpy_s(out[count].name, name_ptr, _TRUNCATE);
            count++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0; // any fault -> treat as unparseable, not a partial result
    }
    return count;
}

// Loads and parses one module's export table fresh -- callers should go
// through load_module_exports_cached() instead; this is the expensive,
// uncached path it wraps.
std::vector<exported_symbol> load_module_exports(const std::wstring &openable_path)
{
    std::vector<exported_symbol> result;
    if (openable_path.empty()) {
        return result;
    }

    HMODULE h = LoadLibraryExW(openable_path.c_str(), nullptr, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (h == nullptr) {
        // Not found, or an architecture mismatch (e.g. a 32-bit module
        // from a WoW64 target being read by this 64-bit-only tool -- see
        // the "32-bit Processes" limitation). Either way, the caller falls
        // back to plain module+offset.
        return result;
    }

    // LOAD_LIBRARY_AS_IMAGE_RESOURCE sets a low tag bit on the returned
    // handle to mark it as resource-only; mask it off to get the real
    // mapped base for reading. FreeLibrary below needs the *original*,
    // unmasked handle -- per its documented contract for this flag.
    BYTE *base = reinterpret_cast<BYTE *>(reinterpret_cast<ULONG_PTR>(h) & ~static_cast<ULONG_PTR>(3));

    auto *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(base);
    auto *nt = reinterpret_cast<IMAGE_NT_HEADERS *>(base + dos->e_lfanew);

    // Reading the DOS/NT/optional headers themselves needs no SEH guard --
    // LoadLibraryExW already validated them structurally to succeed at all.
    if (dos->e_magic == IMAGE_DOS_SIGNATURE && nt->Signature == IMAGE_NT_SIGNATURE) {
        IMAGE_DATA_DIRECTORY export_entry = {};
        if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            export_entry = reinterpret_cast<IMAGE_NT_HEADERS64 *>(nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        }
        else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            export_entry = reinterpret_cast<IMAGE_NT_HEADERS32 *>(nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        }

        if (export_entry.VirtualAddress != 0 && export_entry.Size != 0) {
            auto *exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(base + export_entry.VirtualAddress);

            // Sanity cap, not a realistic limit (even ntdll.dll has under
            // 3000) -- just a bound against a corrupt/hostile NumberOfNames
            // driving an oversized allocation below.
            constexpr DWORD kMaxExports = 16384;
            // Not std::min() -- windows.h's own min/max macros (no NOMINMAX
            // in this project) mangle it into a syntax error.
            DWORD raw_capacity = (exports->NumberOfNames < kMaxExports) ? exports->NumberOfNames : kMaxExports;
            std::vector<raw_export_symbol> raw(raw_capacity);

            DWORD collected = collect_exports_raw(base, export_entry.VirtualAddress, export_entry.Size,
                                                   exports, raw.data(), static_cast<DWORD>(raw.size()));

            result.reserve(collected);
            for (DWORD i = 0; i < collected; i++) {
                result.push_back({ raw[i].rva, std::string(raw[i].name) });
            }
        }
    }

    FreeLibrary(h); // original handle, not the masked `base` -- see above

    std::sort(result.begin(), result.end(),
              [](const exported_symbol &a, const exported_symbol &b) { return a.rva < b.rva; });

    return result;
}

std::unordered_map<std::string, std::vector<exported_symbol>> g_export_cache;
std::mutex g_export_cache_mutex;

// Reading and parsing a module's exports is real file I/O plus a walk over
// a potentially-large array -- worth avoiding on every single event that
// happens to land in a commonly-referenced module (kernel32.dll, ntdll.dll)
// over a long-running trace, hence the cache. An empty result is cached
// too, so a module we failed to parse once isn't retried on every
// subsequent event referencing it.
std::vector<exported_symbol> load_module_exports_cached(const std::string &module_path)
{
    std::lock_guard<std::mutex> lock(g_export_cache_mutex);
    auto it = g_export_cache.find(module_path);
    if (it != g_export_cache.end()) {
        return it->second;
    }

    std::vector<exported_symbol> exports = load_module_exports(to_openable_path(module_path));
    g_export_cache.emplace(module_path, exports);
    return exports;
}

// Beyond this distance, "nearest preceding export" stops being a useful
// landmark and starts being misleading -- claiming "!SomeFunction+0x50000"
// implies the address is within that function, when it's really just
// somewhere in a large stretch of unexported internal code that happens to
// follow it. Past this, the caller falls back to a bare module+offset
// instead of a specific (mis)attribution.
constexpr uint64_t kMaxSymbolDistance = 0x10000; // 64KB

std::optional<std::string> resolve_nearest_export(const std::string &module_path, uint64_t offset)
{
    std::vector<exported_symbol> exports = load_module_exports_cached(module_path);
    if (exports.empty()) {
        return std::nullopt;
    }

    // exports is sorted by rva ascending -- walk to the last entry at or
    // before `offset`.
    const exported_symbol *nearest = nullptr;
    for (const exported_symbol &sym : exports) {
        if (sym.rva > offset) {
            break;
        }
        nearest = &sym;
    }

    if (nearest == nullptr || (offset - nearest->rva) > kMaxSymbolDistance) {
        return std::nullopt;
    }

    std::ostringstream oss;
    oss << nearest->name;
    uint64_t delta = offset - nearest->rva;
    if (delta != 0) {
        oss << "+0x" << std::hex << delta;
    }
    return oss.str();
}

// populated: g_process_modules[pid] now holds a fresh live snapshot.
// access_denied: the process is still running, but OpenProcess() was
//   refused -- confirmed live to mean Protected Process Light (WinTcb
//   level), for exactly the system processes this matters for (csrss.exe,
//   wininit.exe, winlogon.exe). enable_debug_privilege() succeeding does
//   NOT change this outcome: SeDebugPrivilege only bypasses normal
//   discretionary access control, not PPL, which is a categorically
//   stronger, deliberately un-bypassable boundary -- no Administrator
//   process, privileged or not, can OpenProcess() a WinTcb-level process.
//   This is expected, permanent behavior, not a bug to keep chasing.
// unavailable: anything else (most commonly ERROR_INVALID_PARAMETER,
//   meaning the process has already exited by resolution time) -- the
//   ordinary, expected outcome for a short-lived process that's gone by
//   the time the resolver thread gets to it.
enum class live_snapshot_result {
    populated,
    access_denied,
    unavailable,
};

// Fallback for when the passive ETW-based module cache has no confirmed
// main image for a PID -- almost always because the process predates the
// trace. krabs::provider::set_rundown_flags(), the mechanism meant to
// backfill exactly this (a DCStart image-load event replayed for whatever
// was already loaded when the trace started), was tried and confirmed
// empirically not to work for this session type: a diagnostic default
// event callback caught only a handful of unrelated EventTraceGuid
// trace-header events, never anything image-load-shaped. Rather than keep
// chasing that undocumented ETW feature, this asks the OS directly, via
// the standard, documented Process Status API -- works identically
// whether the process predates the trace or not, since it doesn't depend
// on ETW history at all. Overwrites any partial ETW-tracked entries for
// this PID outright rather than merging: if the main image was missing,
// the rest of that PID's ETW-derived module list is equally suspect, and
// a fresh live snapshot is by construction more complete.
live_snapshot_result populate_modules_from_live_snapshot(uint32_t pid)
{
    HANDLE h_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (h_proc == nullptr) {
        return (GetLastError() == ERROR_ACCESS_DENIED) ? live_snapshot_result::access_denied
                                                         : live_snapshot_result::unavailable;
    }

    std::vector<HMODULE> module_handles(256);
    DWORD needed_bytes = 0;

    bool ok = EnumProcessModulesEx(h_proc, module_handles.data(),
        static_cast<DWORD>(module_handles.size() * sizeof(HMODULE)), &needed_bytes, LIST_MODULES_ALL) != 0;

    // The process has more modules than fit in the first pass -- resize to
    // exactly what's needed and retry once.
    if (ok && needed_bytes > module_handles.size() * sizeof(HMODULE)) {
        module_handles.resize(needed_bytes / sizeof(HMODULE));
        ok = EnumProcessModulesEx(h_proc, module_handles.data(),
            static_cast<DWORD>(module_handles.size() * sizeof(HMODULE)), &needed_bytes, LIST_MODULES_ALL) != 0;
    }

    if (!ok) {
        CloseHandle(h_proc);
        return live_snapshot_result::unavailable;
    }

    DWORD module_count = needed_bytes / sizeof(HMODULE);
    std::vector<module_info> snapshot;
    snapshot.reserve(module_count);

    for (DWORD i = 0; i < module_count; i++) {
        MODULEINFO mod_info = {};
        wchar_t path_buf[MAX_PATH] = {};

        if (GetModuleInformation(h_proc, module_handles[i], &mod_info, sizeof(mod_info)) &&
            GetModuleFileNameExW(h_proc, module_handles[i], path_buf, ARRAYSIZE(path_buf)) > 0) {
            std::wstring wpath(path_buf);
            snapshot.push_back({
                reinterpret_cast<uint64_t>(mod_info.lpBaseOfDll),
                static_cast<uint64_t>(mod_info.SizeOfImage),
                std::string(wpath.begin(), wpath.end())
            });
        }
    }

    CloseHandle(h_proc);

    if (snapshot.empty()) {
        return live_snapshot_result::unavailable;
    }

    std::lock_guard<std::mutex> lock(g_process_modules_mutex);
    g_process_modules[pid] = std::move(snapshot);
    return live_snapshot_result::populated;
}

std::string resolve_module_address(uint32_t pid, uint64_t address)
{
    // A cache that merely has *some* entries for this PID isn't enough to
    // trust an "UNBACKED" verdict: under a burst of process creation, a
    // target's ntdll.dll (or another early DLL) can be recorded before its
    // own main executable is, purely due to the cross-CPU delivery race
    // described above. Reporting "possible injected code" off a partially
    // populated cache would be a false positive, so require confirmation
    // that the process's own main image specifically has been recorded
    // before treating "not found in any known module" as meaningful.
    std::string process_name = lookup_process_name(pid);
    std::string expected_main_image = path_filename(process_name);

    auto has_main_image = [&](void) {
        auto it = g_process_modules.find(pid);
        if (it == g_process_modules.end()) {
            return false;
        }
        for (const module_info &m : it->second) {
            if (iequals(path_filename(m.path), expected_main_image)) {
                return true;
            }
        }
        return false;
    };

    bool have_main_image = false;
    if (process_name != "<unknown>") {
        std::lock_guard<std::mutex> lock(g_process_modules_mutex);
        have_main_image = has_main_image();
    }

    live_snapshot_result snapshot_result = live_snapshot_result::unavailable;
    if (!have_main_image && process_name != "<unknown>") {
        snapshot_result = populate_modules_from_live_snapshot(pid);
        if (snapshot_result == live_snapshot_result::populated) {
            std::lock_guard<std::mutex> lock(g_process_modules_mutex);
            have_main_image = has_main_image();
        }
    }

    if (!have_main_image) {
        if (snapshot_result == live_snapshot_result::access_denied) {
            return "<incomplete module info -- target is a Protected Process Light system process "
                   "(e.g. csrss.exe/wininit.exe/winlogon.exe); no privilege level can OpenProcess() it>";
        }
        return "<incomplete module info for this PID -- not recorded by ETW, and no live snapshot available (process likely already exited)>";
    }

    // Only the lookup itself needs g_process_modules_mutex -- copy out the
    // one matching entry and release before doing anything with it.
    // resolve_nearest_export() below can trigger a slow, uncached
    // LoadLibraryExW()+PE-parse (see load_module_exports_cached()), and
    // g_process_modules_mutex is also what handle_image_load_event() needs
    // on the single ETW dispatch thread that processes *every* kernel
    // event (process, thread, and image-load alike -- ProcessTrace()
    // delivers them all on one thread). Holding this lock across that slow
    // work would risk stalling all kernel event processing for however
    // long it takes, undermining the entire point of deferring this
    // resolution off the callback thread in the first place.
    std::optional<module_info> matched_module;
    {
        std::lock_guard<std::mutex> lock(g_process_modules_mutex);
        auto it = g_process_modules.find(pid);
        for (const module_info &m : it->second) {
            if (address >= m.base && address < m.base + m.size) {
                matched_module = m;
                break;
            }
        }
    }

    if (!matched_module.has_value()) {
        return "<UNBACKED -- not inside any known loaded module (possible injected code)>";
    }

    uint64_t offset = address - matched_module->base;
    std::optional<std::string> symbol = resolve_nearest_export(matched_module->path, offset);

    std::ostringstream oss;
    oss << matched_module->path;
    if (symbol.has_value()) {
        oss << "!" << *symbol;
    }
    else {
        oss << "+0x" << std::hex << offset;
    }
    return oss.str();
}

// --- Authenticode signature verification (optional, -s/--verify-signatures) -
//
// "Resolves to a known module" (above) is a necessary check but not a
// sufficient one -- inject_test.py's own loadlibrary mode proves that:
// real injection via kernel32!LoadLibraryA also resolves cleanly to a known
// module. Whether the caller and target are both signed, and by the same
// publisher, is a different and harder-to-fake kind of evidence: it doesn't
// depend on guessing what "normal" looks like from PID/address patterns
// alone.
//
// (See to_openable_path() above -- WinVerifyTrust needs it too, for the
// same NT-device-path reason.)

// Best-effort: the embedded signer certificate's simple display name (e.g.
// "Microsoft Corporation"), or empty if the file has no parseable PKCS#7
// signature blob even though WinVerifyTrust considered it valid (e.g.
// catalog-signed files, where the signature isn't embedded in the file
// itself -- out of scope here since it needs a separate catalog lookup).
std::string get_signer_name(const std::wstring &file_path)
{
    std::string result;

    HCERTSTORE cert_store = nullptr;
    HCRYPTMSG crypt_msg = nullptr;
    DWORD encoding = 0, content_type = 0, format_type = 0;

    if (!CryptQueryObject(
            CERT_QUERY_OBJECT_FILE, file_path.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
            0, &encoding, &content_type, &format_type, &cert_store, &crypt_msg, nullptr)) {
        return result;
    }

    DWORD signer_info_size = 0;
    PCMSG_SIGNER_INFO signer_info = nullptr;

    if (CryptMsgGetParam(crypt_msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signer_info_size)) {
        signer_info = static_cast<PCMSG_SIGNER_INFO>(LocalAlloc(LPTR, signer_info_size));
    }

    if (signer_info != nullptr &&
        CryptMsgGetParam(crypt_msg, CMSG_SIGNER_INFO_PARAM, 0, signer_info, &signer_info_size)) {
        CERT_INFO cert_info = {};
        cert_info.Issuer = signer_info->Issuer;
        cert_info.SerialNumber = signer_info->SerialNumber;

        PCCERT_CONTEXT cert_context = CertFindCertificateInStore(
            cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
            CERT_FIND_SUBJECT_CERT, &cert_info, nullptr);

        if (cert_context != nullptr) {
            wchar_t name_buf[256] = {};
            CertGetNameStringW(cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                                name_buf, ARRAYSIZE(name_buf));
            std::wstring wname(name_buf);
            result = std::string(wname.begin(), wname.end());
            CertFreeCertificateContext(cert_context);
        }
    }

    if (signer_info != nullptr) {
        LocalFree(signer_info);
    }
    CryptMsgClose(crypt_msg);
    CertCloseStore(cert_store, 0);

    return result;
}

struct signature_info {
    bool valid;
    std::string signer; // may be empty even when valid -- see get_signer_name()
};

// Most Windows system binaries (notepad.exe, csrss.exe, ...) are
// catalog-signed rather than Authenticode-embedded: the signature lives in
// a separate .cat file registered against the binary's hash, not inside the
// PE itself. WTD_CHOICE_FILE (embedded-signature check) can't see that at
// all -- confirmed empirically against a genuinely, validly-signed
// notepad.exe, which WinVerifyTrust(WTD_CHOICE_FILE) reports as
// TRUST_E_NOSIGNATURE even though `Get-AuthenticodeSignature` correctly
// shows it as catalog-signed and valid. This walks the same path Windows
// itself uses to check a catalog membership.
//
// Must hash with SHA-256 (CryptCATAdminAcquireContext2 + the matching
// ...FromFileHandle2 calls), not the legacy SHA-1
// CryptCATAdminCalcHashFromFileHandle: modern catalogs are keyed by
// SHA-256. The SHA-1 hash can still resolve to a matching catalog file
// (Windows keeps a legacy lookup index), but the subsequent
// WinVerifyTrust digest check against it then fails with
// TRUST_E_BAD_DIGEST -- also confirmed empirically, the same way.
struct catalog_verify_result {
    bool valid;
    std::wstring catalog_path; // populated only when valid -- see its use in check_authenticode_signature()
};

catalog_verify_result verify_via_catalog(const std::wstring &file_path)
{
    catalog_verify_result result{ false, L"" };

    HCATADMIN cat_admin = nullptr;
    GUID driver_action_verify = DRIVER_ACTION_VERIFY;
    if (!CryptCATAdminAcquireContext2(&cat_admin, &driver_action_verify, L"SHA256", nullptr, 0)) {
        return result;
    }

    HANDLE file_handle = CreateFileW(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                      OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file_handle == INVALID_HANDLE_VALUE) {
        CryptCATAdminReleaseContext(cat_admin, 0);
        return result;
    }

    DWORD hash_len = 0;
    CryptCATAdminCalcHashFromFileHandle2(cat_admin, file_handle, &hash_len, nullptr, 0);
    std::vector<BYTE> hash_buf(hash_len);

    if (hash_len > 0 &&
        CryptCATAdminCalcHashFromFileHandle2(cat_admin, file_handle, &hash_len, hash_buf.data(), 0)) {
        HCATINFO cat_info = CryptCATAdminEnumCatalogFromHash(cat_admin, hash_buf.data(), hash_len, 0, nullptr);

        if (cat_info != nullptr) {
            CATALOG_INFO catalog_info = {};
            catalog_info.cbStruct = sizeof(catalog_info);
            CryptCATCatalogInfoFromContext(cat_info, &catalog_info, 0);

            std::wstring hash_hex;
            wchar_t byte_buf[3];
            for (DWORD i = 0; i < hash_len; i++) {
                swprintf_s(byte_buf, L"%02X", hash_buf[i]);
                hash_hex += byte_buf;
            }

            WINTRUST_CATALOG_INFO catalog_trust_info = {};
            catalog_trust_info.cbStruct = sizeof(catalog_trust_info);
            catalog_trust_info.pcwszCatalogFilePath = catalog_info.wszCatalogFile;
            catalog_trust_info.pcwszMemberTag = hash_hex.c_str();
            catalog_trust_info.pcwszMemberFilePath = file_path.c_str();

            GUID action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            WINTRUST_DATA trust_data = {};
            trust_data.cbStruct = sizeof(trust_data);
            trust_data.dwUIChoice = WTD_UI_NONE;
            trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
            trust_data.dwUnionChoice = WTD_CHOICE_CATALOG;
            trust_data.pCatalog = &catalog_trust_info;
            trust_data.dwStateAction = WTD_STATEACTION_VERIFY;

            result.valid = (WinVerifyTrust(nullptr, &action_guid, &trust_data) == ERROR_SUCCESS);
            if (result.valid) {
                result.catalog_path = catalog_info.wszCatalogFile;
            }

            trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(nullptr, &action_guid, &trust_data);

            CryptCATAdminReleaseCatalogContext(cat_admin, cat_info, 0);
        }
    }

    CloseHandle(file_handle);
    CryptCATAdminReleaseContext(cat_admin, 0);
    return result;
}

// fdwRevocationChecks = WTD_REVOKE_NONE deliberately skips the online CRL/OCSP
// check: this runs per printed event on the resolver thread, and a revocation
// check can block on the network for seconds. That trades "definitely still
// valid right now" for "chain and embedded signature are valid" -- a
// meaningful weakening, but the right side of the tradeoff for an optional,
// best-effort triage signal that must stay usable offline.
signature_info check_authenticode_signature(const std::wstring &file_path)
{
    signature_info result{ false, "" };
    if (file_path.empty()) {
        return result;
    }

    WINTRUST_FILE_INFO file_info = {};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = file_path.c_str();

    GUID action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trust_data = {};
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_SAFER_FLAG;

    LONG status = WinVerifyTrust(nullptr, &action_guid, &trust_data);
    result.valid = (status == ERROR_SUCCESS);

    // Release the verification state regardless of outcome -- required by
    // WinVerifyTrust's contract whenever WTD_STATEACTION_VERIFY was used.
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action_guid, &trust_data);

    // Only fall back to the catalog path for the specific "no embedded
    // signature at all" case -- not any other failure. A file that's
    // actually tampered with or has a broken/revoked embedded signature
    // should stay invalid, not get a second, unrelated verification path
    // that could paper over the real result.
    if (!result.valid && status == TRUST_E_NOSIGNATURE) {
        catalog_verify_result catalog_result = verify_via_catalog(file_path);
        result.valid = catalog_result.valid;

        if (result.valid) {
            // The .cat catalog file is itself an embedded-PKCS7-signed
            // blob -- confirmed empirically: `Get-AuthenticodeSignature`
            // on notepad.exe's own catalog reports SignatureType
            // Authenticode, not Catalog. So get_signer_name() (which only
            // knows how to read an embedded signature) works directly
            // against the catalog file, even though it fails against
            // `file_path` for the same reason the primary check above
            // did -- there's nothing embedded in `file_path` to find.
            result.signer = get_signer_name(catalog_result.catalog_path);
        }

        return result;
    }

    if (result.valid) {
        result.signer = get_signer_name(file_path);
    }

    return result;
}

// process_path is whatever the process-name cache holds for this PID -- a
// real path, a bare image name, or "<unknown>" -- so nullopt here means
// "no file to even try", distinct from a check that ran and failed.
std::optional<signature_info> resolve_signature(const std::string &process_path)
{
    if (process_path.empty() || process_path == "<unknown>") {
        return std::nullopt;
    }
    return check_authenticode_signature(to_openable_path(process_path));
}

void print_one_signature(const char *role, const std::optional<signature_info> &sig)
{
    std::cout << "    " << role << " signature: ";

    if (!sig.has_value()) {
        std::cout << "unavailable (process path unknown)" << std::endl;
    }
    else if (!sig->valid) {
        std::cout << "unsigned/invalid" << std::endl;
    }
    else if (sig->signer.empty()) {
        std::cout << "valid (signer unavailable)" << std::endl;
    }
    else {
        std::cout << "valid (" << sig->signer << ")" << std::endl;
    }
}

// --- Remote thread detection ------------------------------------------------

// Renders a binary blob as a single hex number (big-endian display of the
// little-endian bytes), used as the fallback for property types we don't
// have a dedicated case for below (HEXINT32/64, GUID, SID, FILETIME, ...).
std::string format_binary_hex(const krabs::binary &b)
{
    const auto &bytes = b.bytes();
    if (bytes.empty()) {
        return "<empty>";
    }

    std::ostringstream oss;
    oss << "0x" << std::hex << std::setfill('0');
    for (auto it = bytes.rbegin(); it != bytes.rend(); ++it) {
        oss << std::setw(2) << static_cast<unsigned>(*it);
    }
    return oss.str();
}

// Formats every property on the current event as "name = value" lines,
// type-aware, as insight into the raw ETW payload (e.g. StartAddr/
// Win32StartAddr are the entry point the injected thread begins executing
// at in the target process -- the most actionable field for remote-thread-
// injection triage). Returns plain strings (rather than printing directly)
// because callers may need to capture this after the fact and print it
// later, once the EVENT_RECORD backing `parser` is no longer valid.
std::vector<std::string> format_event_payload(krabs::parser &parser)
{
    std::vector<std::string> lines;

    for (const krabs::property &prop : parser.properties()) {
        std::wstring wname = prop.name();
        std::string name(wname.begin(), wname.end());

        std::ostringstream line;
        line << name << " = ";

        try {
            switch (prop.type()) {
            case TDH_INTYPE_UNICODESTRING: {
                std::wstring v = parser.parse<std::wstring>(wname);
                line << std::string(v.begin(), v.end());
                break;
            }
            case TDH_INTYPE_ANSISTRING:
                line << parser.parse<std::string>(wname);
                break;
            case TDH_INTYPE_POINTER: {
                krabs::pointer v = parser.parse<krabs::pointer>(wname);
                line << "0x" << std::hex << v.address << std::dec;
                break;
            }
            case TDH_INTYPE_INT8:
                line << static_cast<int>(parser.parse<int8_t>(wname));
                break;
            case TDH_INTYPE_UINT8:
                line << static_cast<unsigned>(parser.parse<uint8_t>(wname));
                break;
            case TDH_INTYPE_INT16:
                line << parser.parse<int16_t>(wname);
                break;
            case TDH_INTYPE_UINT16:
                line << parser.parse<uint16_t>(wname);
                break;
            case TDH_INTYPE_INT32:
                line << parser.parse<int32_t>(wname);
                break;
            case TDH_INTYPE_UINT32:
                line << parser.parse<uint32_t>(wname);
                break;
            case TDH_INTYPE_INT64:
                line << parser.parse<int64_t>(wname);
                break;
            case TDH_INTYPE_UINT64:
                line << parser.parse<uint64_t>(wname);
                break;
            case TDH_INTYPE_FLOAT:
                line << parser.parse<float>(wname);
                break;
            case TDH_INTYPE_DOUBLE:
                line << parser.parse<double>(wname);
                break;
            case TDH_INTYPE_BOOLEAN:
                line << (parser.parse<bool>(wname) ? "true" : "false");
                break;
            default:
                line << format_binary_hex(parser.parse<krabs::binary>(wname))
                     << "  (" << krabs::in_type_to_string(prop.type()) << ")";
                break;
            }
        }
        catch (const std::exception &ex) {
            line << "<unavailable: " << ex.what() << ">";
        }

        lines.push_back(line.str());
    }

    return lines;
}

void print_event_payload(krabs::parser &parser)
{
    for (const std::string &line : format_event_payload(parser)) {
        std::cout << "      " << line << std::endl;
    }
}

// --- Deferred resolution -----------------------------------------------
//
// A freshly created process's own Image-Load events can be delivered to us
// slightly *after* its Thread-Start event: ETW only guarantees ordering
// within a single CPU's buffer, not across CPUs, so two providers racing on
// two different cores can arrive at ProcessTrace() interleaved out of
// "real" chronological order. Resolving Win32StartAddr synchronously
// inside handle_thread_event therefore misses the module cache for almost
// every brand-new target process (see the repeated "no module info cached"
// results in practice). Instead, the full event is captured into a plain
// struct up front -- property values only, since the EVENT_RECORD/schema/
// parser are only valid for the duration of the callback -- and
// resolution+printing is deferred to a background thread after a short
// grace period, giving the target's own image-load events time to land.

constexpr std::chrono::milliseconds kResolveDelay(300);

struct pending_event {
    uint32_t caller_pid;
    std::string caller_name;
    uint32_t target_pid;
    std::string target_name;
    bool has_start_addr;
    uint64_t start_addr;
    // Not resolved here -- is_initial_process_thread() depends on the
    // process-name cache, which is populated by a *different* provider
    // (process_provider) than this thread-create event came from, and is
    // therefore subject to the same cross-CPU delivery race that motivates
    // kResolveDelay for Win32StartAddr resolution below. Checking it
    // synchronously here, before that race has had a chance to resolve,
    // was a real bug: a target process's Thread-Start event can easily
    // arrive before its own Process-Start event has been processed, making
    // a genuine initial thread look like it isn't one. Recomputed in
    // print_pending_event() instead, after the same grace period.
    int64_t thread_event_time;
    bool is_kernel_mode_target;
    bool is_same_image;
    std::vector<std::string> payload_lines;
    std::chrono::steady_clock::time_point due_time;
};

std::deque<pending_event> g_pending_events;
std::mutex g_pending_mutex;
std::condition_variable g_pending_cv;
std::atomic<bool> g_shutdown{ false };

void print_pending_event(const pending_event &ev)
{
    // Resolved here, not in handle_thread_event -- see the comment on
    // pending_event::thread_event_time. By now the resolver thread has
    // already waited out kResolveDelay for this event, giving the target's
    // Process-Start event (a different provider, racing on a different
    // CPU) the same grace period Win32StartAddr resolution gets below to
    // actually land in the process-name cache.
    initial_thread_diagnosis initial_diag =
        diagnose_initial_process_thread(ev.target_pid, ev.caller_pid, ev.thread_event_time);
    bool is_initial_thread = initial_diag.is_initial_thread;

    // Resolved once up front (rather than inside the printing block below)
    // because is_same_image's suppression decision needs the result too --
    // see signer_confirmed_same_image.
    std::optional<signature_info> caller_sig, target_sig;
    if (g_verify_signatures) {
        caller_sig = resolve_signature(ev.caller_name);
        target_sig = resolve_signature(ev.target_name);
    }

    // is_same_image alone is a weak, spoofable signal (see the comment on
    // is_same_image's assignment in handle_thread_event) -- an attacker can
    // trivially spawn a copy of any trusted binary as a decoy child. But
    // same-image *and* a valid, matching Authenticode signature on both
    // sides is different, much harder evidence to fake: forging that
    // requires an actual compromised signing certificate, not just copying
    // a path. That combination gets the same treatment as the two
    // structural filters below -- suppressed by default, visible under -v --
    // rather than is_same_image's own always-shown, distinctly-labeled
    // treatment. Only reachable at all when -s/--verify-signatures is on;
    // without it there's no signature evidence to promote the verdict with.
    bool signer_confirmed_same_image =
        ev.is_same_image && caller_sig.has_value() && target_sig.has_value() &&
        caller_sig->valid && target_sig->valid && !caller_sig->signer.empty() &&
        iequals(caller_sig->signer, target_sig->signer);

    // Weaker than signer_confirmed_same_image on purpose: two different
    // binaries sharing a publisher (e.g. an HP background service creating
    // a thread in a sibling HP host process, both "HP Inc.") is a common,
    // usually-benign pattern -- a vendor's own components talking to each
    // other -- but "signed by the same company" is a much broader claim
    // than "the same file". A publisher can ship many binaries; a
    // vulnerable or older one being abused as a launcher against a newer
    // one would look identical by this signal alone. So this stays in
    // is_same_image's always-shown, labeled-not-suppressed tier, never
    // signer_confirmed_same_image's suppressed one.
    bool same_publisher_different_image =
        !ev.is_same_image && caller_sig.has_value() && target_sig.has_value() &&
        caller_sig->valid && target_sig->valid && !caller_sig->signer.empty() &&
        iequals(caller_sig->signer, target_sig->signer);

    // is_kernel_mode_target is suppressed by default back in
    // handle_thread_event (self-contained in the event's own payload, no
    // race to wait out). is_initial_thread and signer_confirmed_same_image
    // are suppressed here instead, once their evidence is actually
    // available -- both are noise, not injection, same as
    // is_kernel_mode_target and SYSTEM_PID. Plain is_same_image (no
    // signature match, or -s not enabled) is different -- always shown,
    // just labeled distinctly.
    if ((is_initial_thread || signer_confirmed_same_image) && !g_verbose) {
        return;
    }

    // Resolved before acquiring cout_lock below, same reasoning as
    // caller_sig/target_sig above: resolve_module_address() can trigger
    // real, possibly-slow work (an uncached PE export parse, a live
    // process snapshot), and doing that while holding g_cout_mutex would
    // needlessly delay the stats thread's and the ETW callback thread's
    // own (rarer) output for no reason.
    std::optional<std::string> resolved_start_addr;
    if (!ev.is_kernel_mode_target && ev.has_start_addr) {
        resolved_start_addr = resolve_module_address(ev.target_pid, ev.start_addr);
    }

    // Held for the rest of this function -- see g_cout_mutex's comment.
    std::lock_guard<std::mutex> cout_lock(g_cout_mutex);

    const char *label = "[!] Remote thread created: ";
    if (ev.is_kernel_mode_target) {
        label = "[i] Kernel-mode system thread, not a usermode injection target: ";
    }
    else if (is_initial_thread) {
        label = "[i] Initial thread of newly created process (not injection): ";
    }
    else if (signer_confirmed_same_image) {
        label = "[i] Same-image thread, signer-verified (not injection): ";
    }
    else if (ev.is_same_image) {
        label = "[?] Same-image parent->child thread (common in sandboxed multi-process apps; not auto-verified): ";
    }
    else if (same_publisher_different_image) {
        label = "[?] Cross-component same-publisher thread (different binaries, matching signer; not auto-verified): ";
    }

    std::cout << label
              << "caller PID=" << ev.caller_pid << " (" << ev.caller_name << ")"
              << "  target PID=" << ev.target_pid << " (" << ev.target_name << ")"
              << std::endl;

    // Explains *why* is_initial_thread came out the way it did, rather than
    // leaving the verdict unexplained -- particularly useful for telling
    // apart "target's Process-Start event still isn't in the cache" (the
    // race this check lost to once already) from "it's there, but the
    // recorded ParentId or timing genuinely didn't match" (a structurally
    // different, later thread into an already-running process).
    if (g_verbose) {
        std::cout << "    [diag] initial-thread check: ";
        if (!initial_diag.found_process_start_info) {
            std::cout << "target's Process-Start event not in cache yet" << std::endl;
        }
        else {
            std::cout << "recorded ParentId=" << initial_diag.recorded_parent_id
                       << " (caller=" << ev.caller_pid
                       << ", match=" << (initial_diag.recorded_parent_id == ev.caller_pid ? "yes" : "no") << ")"
                       << "  time delta=" << (initial_diag.delta_100ns / 10000) << "ms"
                       << "  verdict=" << (initial_diag.is_initial_thread ? "initial thread" : "not initial thread")
                       << std::endl;
        }
    }

    if (iequals(path_filename(ev.caller_name), "svchost.exe")) {
        std::optional<std::string> service_group =
            extract_svchost_service_group(lookup_process_command_line(ev.caller_pid));
        if (service_group.has_value()) {
            std::cout << "    Caller svchost service group: -k " << *service_group << std::endl;
        }
    }

    if (ev.is_kernel_mode_target) {
        // Module resolution would never succeed -- this target has no
        // usermode image to load one -- so don't even try; just show the
        // raw kernel-mode entry point for reference.
        std::cout << "    Win32StartAddr = 0x" << std::hex << ev.start_addr << std::dec
                  << "  (kernel-mode address; no usermode module cache applies)"
                  << std::endl;
    }
    else if (resolved_start_addr.has_value()) {
        std::cout << "    Win32StartAddr -> " << *resolved_start_addr << std::endl;
    }

    if (g_verify_signatures) {
        print_one_signature("Caller", caller_sig);
        print_one_signature("Target", target_sig);

        if (caller_sig.has_value() && target_sig.has_value() &&
            caller_sig->valid && target_sig->valid && !caller_sig->signer.empty()) {
            std::cout << "    Signer match: " << (iequals(caller_sig->signer, target_sig->signer) ? "yes" : "no")
                      << std::endl;
        }
    }

    for (const std::string &line : ev.payload_lines) {
        std::cout << "      " << line << std::endl;
    }
}

void queue_pending_event(pending_event ev)
{
    {
        std::lock_guard<std::mutex> lock(g_pending_mutex);
        g_pending_events.push_back(std::move(ev));
    }
    g_pending_cv.notify_all();
}

// Waits for each event's grace period to elapse, then resolves and prints
// it in order. On shutdown, whatever is left in the queue is flushed
// immediately rather than dropped.
void resolver_thread_func()
{
    std::unique_lock<std::mutex> lock(g_pending_mutex);

    while (!g_shutdown) {
        if (g_pending_events.empty()) {
            g_pending_cv.wait(lock, [] { return g_shutdown.load() || !g_pending_events.empty(); });
            continue;
        }

        auto due_time = g_pending_events.front().due_time;
        bool shutdown_requested = g_pending_cv.wait_until(lock, due_time, [] { return g_shutdown.load(); });

        if (shutdown_requested) {
            break;
        }
        if (g_pending_events.empty()) {
            continue;
        }

        pending_event ev = std::move(g_pending_events.front());
        g_pending_events.pop_front();

        lock.unlock();
        print_pending_event(ev);
        lock.lock();
    }

    while (!g_pending_events.empty()) {
        pending_event ev = std::move(g_pending_events.front());
        g_pending_events.pop_front();

        lock.unlock();
        print_pending_event(ev);
        lock.lock();
    }
}

// Some ETW-visible "processes" (MemCompression, Secure System, Registry) are
// kernel-mode minimal/pico processes: containers the memory manager or
// kernel uses internally, with no executable image and no usermode context.
// The kernel spins up worker threads inside them routinely (e.g. the Store
// Manager, driven by the SysMain service in some svchost.exe, scaling
// MemCompression's compression workers with memory pressure) -- caller PID
// != target PID every time, which looks exactly like remote-thread injection
// by PID pattern alone.
//
// It isn't, and can't be: CreateRemoteThread()/NtCreateThreadEx() from
// usermode can only point a thread at a usermode address. A thread with no
// usermode stack/TEB was created directly by kernel code, a path no
// usermode injection technique can reach. Rather than hardcode the handful
// of known pico-process names (which Windows has added to over the years),
// this checks for the actual invariant: a real usermode thread always has a
// nonzero user stack and TEB, allocated before it ever runs a single
// instruction. It's also why resolving Win32StartAddr against the target's
// module cache is pointless here -- these targets never load a usermode
// image, so "main executable not yet recorded" would never stop being true.
bool is_kernel_mode_target(krabs::parser &parser)
{
    uint64_t user_stack_base = 0;
    uint64_t teb_base = 0;

    // Require both fields to have actually parsed -- a thread we simply
    // failed to read fields for is "unknown", not "kernel-mode".
    bool got_stack = try_parse_as_address(parser, L"UserStackBase", user_stack_base);
    bool got_teb = try_parse_as_address(parser, L"TebBase", teb_base);

    return got_stack && got_teb && user_stack_base == 0 && teb_base == 0;
}

void handle_thread_event(const EVENT_RECORD &record, const krabs::trace_context &trace_context)
{
    krabs::schema schema(record, trace_context.schema_locator);

    if (schema.event_opcode() != 1) { // Start only
        return;
    }

    krabs::parser parser(schema);
    uint32_t target_pid = 0;

    if (!parser.try_parse(L"ProcessId", target_pid)) {
        return;
    }

    uint32_t caller_pid = record.EventHeader.ProcessId;

    if (caller_pid != target_pid) {
        if (caller_pid == SYSTEM_PID && !g_verbose) {
            return;
        }

        bool is_kernel_target = is_kernel_mode_target(parser);
        if (is_kernel_target && !g_verbose) {
            return;
        }

        // Deliberately NOT checking is_initial_process_thread() here -- see
        // the comment on pending_event::thread_event_time. It's resolved
        // later, in print_pending_event(), after the same grace period
        // Win32StartAddr resolution already waits out for exactly this kind
        // of cross-provider race.

        pending_event ev;
        ev.caller_pid = caller_pid;
        ev.caller_name = lookup_process_name(caller_pid);
        ev.target_pid = target_pid;
        ev.target_name = lookup_process_name(target_pid);
        ev.thread_event_time = record.EventHeader.TimeStamp.QuadPart;
        ev.is_kernel_mode_target = is_kernel_target;
        ev.is_same_image = (ev.caller_name != "<unknown>") &&
                            iequals(strip_volume_prefix(ev.caller_name), strip_volume_prefix(ev.target_name));

        krabs::pointer start_addr;
        ev.has_start_addr = parser.try_parse(L"Win32StartAddr", start_addr);
        ev.start_addr = ev.has_start_addr ? start_addr.address : 0;

        ev.payload_lines = format_event_payload(parser);
        ev.due_time = std::chrono::steady_clock::now() + kResolveDelay;

        queue_pending_event(std::move(ev));
    }
}

// --- Trace session tuning ---------------------------------------------------
//
// Left at defaults (BufferSize/MinimumBuffers/MaximumBuffers/FlushTimer all
// 0), ETW auto-sizes buffers based on CPU count -- a reasonable baseline,
// but with no real headroom for bursts. This session watches process,
// thread, *and* image-load activity system-wide on one logger, so a burst
// of process churn (a build running, many processes launching/exiting close
// together) is exactly the kind of load that can overrun auto-sized
// buffers, silently dropping events (see EventsLost tracking below -- the
// only way to notice this actually happened). Scaling buffer counts by CPU
// count keeps the tuning reasonable across different machines rather than
// hardcoding one value.
EVENT_TRACE_PROPERTIES build_tuned_trace_properties()
{
    SYSTEM_INFO sys_info = {};
    GetSystemInfo(&sys_info);
    DWORD cpu_count = (sys_info.dwNumberOfProcessors > 0) ? sys_info.dwNumberOfProcessors : 1;

    EVENT_TRACE_PROPERTIES properties = {};
    properties.BufferSize = 128;              // KB per buffer
    properties.MinimumBuffers = cpu_count * 4; // OS-enforced floor is 2/CPU; give real headroom above it
    properties.MaximumBuffers = cpu_count * 8;
    properties.FlushTimer = 1;                // seconds -- keep real-time output responsive
    return properties;
}

// --- EventsLost tracking -----------------------------------------------
//
// query_stats() asks ETW directly for the session's current counters (via
// ControlTrace(..., EVENT_TRACE_CONTROL_QUERY)), so this reflects buffer
// overruns even though our own callbacks never see the dropped events --
// that's the whole point: EventsLost is invisible from inside
// handle_*_event, it can only be observed by asking the session itself.

constexpr std::chrono::seconds kStatsLogInterval(30);

std::mutex g_stats_mutex;
std::condition_variable g_stats_cv;

void log_trace_stats(const krabs::trace_stats &stats, uint32_t &last_events_lost)
{
    // See g_cout_mutex's comment -- held for both lines below, so this
    // block can't interleave with a print_pending_event() block underway
    // on the resolver thread.
    std::lock_guard<std::mutex> cout_lock(g_cout_mutex);

    std::cout << "[stats] events handled=" << stats.eventsHandled
              << "  events lost=" << stats.eventsLost
              << "  buffers written=" << stats.buffersWritten
              << "  buffers lost=" << stats.buffersLost
              << "  buffers free=" << stats.buffersFree << "/" << stats.buffersCount
              << std::endl;

    if (stats.eventsLost > last_events_lost) {
        std::cerr << "[!] WARNING: " << (stats.eventsLost - last_events_lost)
                  << " ETW event(s) lost since the last check (total " << stats.eventsLost
                  << ") -- buffers are being overrun faster than they're drained. "
                     "Consider raising BufferSize/MinimumBuffers in "
                     "build_tuned_trace_properties(), or reducing what's monitored."
                  << std::endl;
    }

    last_events_lost = stats.eventsLost;
}

void stats_thread_func(krabs::kernel_trace &trace)
{
    std::unique_lock<std::mutex> lock(g_stats_mutex);
    uint32_t last_events_lost = 0;

    while (!g_stats_cv.wait_for(lock, kStatsLogInterval, [] { return g_shutdown.load(); })) {
        lock.unlock();
        log_trace_stats(trace.query_stats(), last_events_lost);
        lock.lock();
    }
}

int main(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-v" || arg == "--verbose") {
            g_verbose = true;
        }
        else if (arg == "-s" || arg == "--verify-signatures") {
            g_verify_signatures = true;
        }
    }

    if (!enable_debug_privilege()) {
        std::cerr << "[!] Warning: could not enable SeDebugPrivilege -- "
                     "module resolution for protected system processes "
                     "(wininit.exe, winlogon.exe, csrss.exe) will stay "
                     "unavailable even though this process is elevated."
                  << std::endl;
    }

    krabs::kernel_trace trace(L"RemoteThreadTrace");

    EVENT_TRACE_PROPERTIES tuned_properties = build_tuned_trace_properties();
    trace.set_trace_properties(&tuned_properties); // must precede enable()/start()

    krabs::kernel::process_provider process_provider;
    process_provider.add_on_event_callback(handle_process_event);

    krabs::kernel::thread_provider thread_provider;
    thread_provider.add_on_event_callback(handle_thread_event);

    krabs::kernel::image_load_provider image_load_provider;
    image_load_provider.add_on_event_callback(handle_image_load_event);

    // Pre-existing processes' modules are backfilled on demand via
    // populate_modules_from_live_snapshot() inside resolve_module_address()
    // instead of via ETW rundown -- see that function's comment for why:
    // krabs::provider::set_rundown_flags() was tried first and confirmed,
    // empirically, not to produce usable events for this session type.

    // All providers on one session/logger, per the multi-provider pattern
    // Microsoft's own Office 365 Security team uses in production.
    trace.enable(process_provider);
    trace.enable(thread_provider);
    trace.enable(image_load_provider);

    g_trace = &trace;
    if (!SetConsoleCtrlHandler(console_ctrl_handler, TRUE)) {
        std::cerr << "[!] Warning: failed to install Ctrl+C handler -- "
                     "an interrupted run may leave the ETW session orphaned."
                  << std::endl;
    }

    std::thread resolver_thread(resolver_thread_func);
    std::thread stats_thread(stats_thread_func, std::ref(trace));

    std::cout << "Monitoring for remote thread creation... (Ctrl+C to stop)" << std::endl;
    if (g_verbose) {
        std::cout << "Verbose mode: including remote threads originating from System (PID 4)" << std::endl;
    }
    if (g_verify_signatures) {
        std::cout << "Signature verification enabled: checking caller/target Authenticode "
                     "signatures per event (adds latency)" << std::endl;
    }
    trace.start(); // blocks until trace.stop() is called (see console_ctrl_handler)

    g_shutdown = true;
    g_pending_cv.notify_all();
    g_stats_cv.notify_all();
    resolver_thread.join();
    stats_thread.join();

    std::cout << "Trace stopped." << std::endl;
    return 0;
}
