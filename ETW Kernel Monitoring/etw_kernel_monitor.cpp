// ============================================================================
//  etw_kernel_monitor.cpp
//	Author: Ghanashyam Satpathy
//  Real-time ETW consumer using a CUSTOM session name (not KERNEL_LOGGER_NAME).
//  Enables Process, File I/O and Registry kernel providers individually via
//  EnableTraceEx2, and parses event payloads with TDH helpers.
//
//  Build (MSVC x64 Developer Command Prompt — run as Administrator):
//      cl /EHsc /W4 /std:c++17 /O2 etw_kernel_monitor.cpp ^
//         advapi32.lib tdh.lib ole32.lib /Fe:etw_kernel_monitor.exe
//
//  Run (elevated):
//      etw_kernel_monitor.exe
//      Press Ctrl+C to stop.
// ============================================================================

// ─── logman: enumerate & troubleshoot ETW sessions ───────────────────────────
//
//  An ETW session is a kernel-managed object, not tied to the lifetime of the
//  process that created it -- StartTrace() registers it and it keeps running
//  system-wide until something explicitly stops it. If this process is killed
//  or crashes before Shutdown() runs, the session (name: k_SessionName below,
//  "MyProduct_KernelMonitor") is orphaned: still consuming buffers, but with
//  no consumer reading from it. StartSession()'s ERROR_ALREADY_EXISTS branch
//  handles this in-code on next launch, but `logman` is the manual, outside-
//  the-process equivalent -- useful when you want to inspect or intervene
//  without running this tool at all. All commands need an elevated prompt.
//
//  List every ETW session currently running on the machine (ours plus any
//  other tool's -- Defender, sysmon, profilers, etc. all show up here):
//      logman query -ets
//
//  Query this session specifically -- while it's running, shows which
//  providers are enabled, with what keywords/level, and buffer settings:
//      logman query "MyProduct_KernelMonitor" -ets
//
//  Force-stop this session manually -- the fix for "StartTrace failed:
//  ERROR_ALREADY_EXISTS" if you'd rather clear it by hand than let
//  StartSession()'s automatic recovery do it on the next run:
//      logman stop "MyProduct_KernelMonitor" -ets
//
//  List every ETW provider registered on the system -- confirms a provider
//  name/GUID resolves at all, or find one by partial name:
//      logman query providers
//      logman query providers | findstr /i "Kernel-Process"
//
//  Dump one provider's keyword/level/task table from its live manifest --
//  the way to independently verify the PROC_KW_*/FILE_KW_*/REG_KW_* keyword
//  values hardcoded above still match this machine's Windows build, since
//  they come from the provider's manifest, not a public, versioned ABI:
//      logman query providers "Microsoft-Windows-Kernel-Process"
//      logman query providers "Microsoft-Windows-Kernel-File"
//      logman query providers "Microsoft-Windows-Kernel-Registry"
//
//  If StartTrace() fails with something other than ERROR_ALREADY_EXISTS or
//  ERROR_ACCESS_DENIED (not elevated), `logman query -ets` doubling as a
//  session count is the next thing to check -- Windows caps the number of
//  concurrent ETW trace sessions (historically 64); a heavily-instrumented
//  machine (EDR, multiple profilers) can genuinely hit that ceiling.

#define UNICODE
#define _UNICODE
#define INITGUID

#include <windows.h>
#include <evntrace.h>       // StartTrace / EnableTraceEx2 / OpenTrace / ProcessTrace
#include <evntcons.h>       // EVENT_RECORD, PEVENT_RECORD
#include <tdh.h>            // TdhGetEventInformation / TdhFormatProperty
#include <objbase.h>        // CoCreateGuid

#include <fcntl.h>          // _O_U16TEXT
#include <io.h>             // _setmode / _fileno

#include <iostream>
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <mutex>
#include <iomanip>
#include <cstdlib>
#include <cstring>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "ole32.lib")

// ─── Session identity ─────────────────────────────────────────────────────────

static const WCHAR* k_SessionName = L"MyProduct_KernelMonitor";

// ─── Modern kernel provider GUIDs ────────────────────────────────────────────
//
//  These replace the legacy KERNEL_LOGGER_NAME singleton approach.
//  Each provider can be enabled/disabled independently via EnableTraceEx2.

// Microsoft-Windows-Kernel-Process  {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
static const GUID k_ProcessProviderGuid =
    { 0x22fb2cd6, 0x0e7b, 0x422b,
      { 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 } };

// Microsoft-Windows-Kernel-File     {EDD08927-9CC4-4E65-B970-C2560FB59702}
static const GUID k_FileProviderGuid =
    { 0xedd08927, 0x9cc4, 0x4e65,
      { 0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0x97, 0x02 } };

// Microsoft-Windows-Kernel-Registry {70EB4F03-C1DE-4F73-A051-33D13D5413BD}
static const GUID k_RegistryProviderGuid =
    { 0x70eb4f03, 0xc1de, 0x4f73,
      { 0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd } };

// ─── Provider keywords ────────────────────────────────────────────────────────
//
//  Each provider defines its own keyword bitmask (see provider manifest via
//  "wevtutil gp <ProviderName>" or TDH).  Values below are the stable,
//  documented masks for these three providers on Windows 10+.

// Kernel-Process keywords
static const ULONGLONG PROC_KW_PROCESS     = 0x10;   // ProcessStart / ProcessStop
static const ULONGLONG PROC_KW_THREAD      = 0x20;   // ThreadStart / ThreadStop
static const ULONGLONG PROC_KW_IMAGE_LOAD  = 0x40;   // Image (DLL/EXE) load/unload

// Kernel-File keywords
static const ULONGLONG FILE_KW_READ        = 0x0001; // Read I/O
static const ULONGLONG FILE_KW_WRITE       = 0x0002; // Write I/O
static const ULONGLONG FILE_KW_CREATE      = 0x0004; // Create/Open
static const ULONGLONG FILE_KW_CLOSE       = 0x0010; // Close/Cleanup
static const ULONGLONG FILE_KW_DELETE      = 0x0100; // Delete
static const ULONGLONG FILE_KW_RENAME      = 0x0200; // Rename
static const ULONGLONG FILE_KW_DIR_ENUM    = 0x0400; // Directory enumeration
static const ULONGLONG FILE_KW_FLUSH       = 0x0800; // Flush buffers
static const ULONGLONG FILE_KW_QUERY_INFO  = 0x1000; // QueryInformation
static const ULONGLONG FILE_KW_SET_INFO    = 0x2000; // SetInformation
static const ULONGLONG FILE_KW_NAME        = 0x8000; // Filename resolution events

// Kernel-Registry keywords
static const ULONGLONG REG_KW_CREATE_KEY   = 0x0001;
static const ULONGLONG REG_KW_OPEN_KEY     = 0x0002;
static const ULONGLONG REG_KW_DELETE_KEY   = 0x0004;
static const ULONGLONG REG_KW_QUERY_KEY    = 0x0008;
static const ULONGLONG REG_KW_SET_VALUE    = 0x0010;
static const ULONGLONG REG_KW_DELETE_VALUE = 0x0020;
static const ULONGLONG REG_KW_QUERY_VALUE  = 0x0040;
static const ULONGLONG REG_KW_ENUM_KEY     = 0x0100;
static const ULONGLONG REG_KW_ENUM_VALUE   = 0x0200;
static const ULONGLONG REG_KW_CLOSE_KEY    = 0x0800;

// ─── Globals ──────────────────────────────────────────────────────────────────

static TRACEHANDLE        g_hSession = INVALID_PROCESSTRACE_HANDLE;
static TRACEHANDLE        g_hTrace   = INVALID_PROCESSTRACE_HANDLE;
static std::atomic<bool>  g_running(true);
static std::mutex         g_printMtx;

// NT Kernel event opcodes — Process
constexpr UCHAR PROC_OPCODE_START = 1;
constexpr UCHAR PROC_OPCODE_STOP = 2;
// NT Kernel event opcodes — File I/O (classic MOF-based)
constexpr UCHAR FILE_OPCODE_CREATE = 64;
constexpr UCHAR FILE_OPCODE_CLEANUP = 65;
constexpr UCHAR FILE_OPCODE_CLOSE = 66;
constexpr UCHAR FILE_OPCODE_READ = 67;
constexpr UCHAR FILE_OPCODE_WRITE = 68;
constexpr UCHAR FILE_OPCODE_SET_INFO = 69;
constexpr UCHAR FILE_OPCODE_DELETE = 70;
constexpr UCHAR FILE_OPCODE_RENAME = 71;
constexpr UCHAR FILE_OPCODE_MKDIR = 72;
constexpr UCHAR FILE_OPCODE_FILEIO_NAME = 0;   // filename-resolution event
// NT Kernel event opcodes — Registry
constexpr UCHAR REG_OPCODE_CREATE = 1;
constexpr UCHAR REG_OPCODE_OPEN = 2;
constexpr UCHAR REG_OPCODE_DELETE_KEY = 3;
constexpr UCHAR REG_OPCODE_QUERY = 4;
constexpr UCHAR REG_OPCODE_SET_VALUE = 5;
constexpr UCHAR REG_OPCODE_DELETE_VALUE = 6;
constexpr UCHAR REG_OPCODE_QUERY_VALUE = 7;
constexpr UCHAR REG_OPCODE_CLOSE = 12;

// ─── Utility helpers ──────────────────────────────────────────────────────────

// Format FILETIME (100-ns ticks since 1601) as HH:MM:SS.mmm
static std::wstring FormatTimestamp(const LARGE_INTEGER& li)
{
    FILETIME ft;
    ft.dwLowDateTime  = static_cast<DWORD>(li.QuadPart & 0xFFFFFFFF);
    ft.dwHighDateTime = static_cast<DWORD>(li.QuadPart >> 32);
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    WCHAR buf[32];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE,
        L"%02u:%02u:%02u.%03u",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

static bool GuidEqual(const GUID& a, const GUID& b)
{
    return memcmp(&a, &b, sizeof(GUID)) == 0;
}

// Map a provider GUID to a display label
static const wchar_t* ProviderLabel(const GUID& g)
{
    if (GuidEqual(g, k_ProcessProviderGuid))  return L"PROCESS ";
    if (GuidEqual(g, k_FileProviderGuid))     return L"FILE_IO ";
    if (GuidEqual(g, k_RegistryProviderGuid)) return L"REGISTRY";
    return L"UNKNOWN ";
}

// ─── TDH: walk and print all properties for an event ─────────────────────────
//
//  Two-pass TdhGetEventInformation to get the schema, then iterates every
//  top-level property, calls TdhGetEventMapInformation for enum/bitfield maps,
//  and TdhFormatProperty for the formatted value.  Critically, it tracks the
//  UserData pointer by the `consumed` bytes returned by TdhFormatProperty so
//  each successive property decodes from the right offset.

static void PrintPropertiesTDH(PEVENT_RECORD pEvent)
{
    // ── Pass 1: get required buffer size ──────────────────────────────────────
    ULONG              infoSize = 0;
    PTRACE_EVENT_INFO  pInfo    = nullptr;

    ULONG status = TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &infoSize);
    if (status != ERROR_INSUFFICIENT_BUFFER || infoSize == 0)
        return;

    pInfo = reinterpret_cast<PTRACE_EVENT_INFO>(malloc(infoSize));
    if (!pInfo) return;

    // ── Pass 2: fetch the actual schema ───────────────────────────────────────
    status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &infoSize);
    if (status != ERROR_SUCCESS) { free(pInfo); return; }

    // Print provider / event names if the manifest provides them
    if (pInfo->ProviderNameOffset)
        std::wcout << L"    Provider  : "
                   << reinterpret_cast<PWCHAR>(
                          reinterpret_cast<BYTE*>(pInfo)
                          + pInfo->ProviderNameOffset) << L"\n";

    if (pInfo->EventNameOffset)
        std::wcout << L"    EventName : "
                   << reinterpret_cast<PWCHAR>(
                          reinterpret_cast<BYTE*>(pInfo)
                          + pInfo->EventNameOffset) << L"\n";

    // ── Walk properties ───────────────────────────────────────────────────────
    PBYTE  pUserData    = reinterpret_cast<PBYTE>(pEvent->UserData);
    USHORT userDataLeft = static_cast<USHORT>(pEvent->UserDataLength);

    for (ULONG i = 0;
         i < pInfo->TopLevelPropertyCount && userDataLeft > 0;
         ++i)
    {
        const EVENT_PROPERTY_INFO& pi = pInfo->EventPropertyInfoArray[i];

        PWCHAR propName = reinterpret_cast<PWCHAR>(
            reinterpret_cast<BYTE*>(pInfo) + pi.NameOffset);

        // Skip struct containers — their members are flattened into the array
        if (pi.Flags & PropertyStruct) {
            std::wcout << L"    [struct]  " << propName << L"\n";
            continue;
        }

        // ── Resolve enum / bitfield map (optional) ────────────────────────────
        PEVENT_MAP_INFO pMap = nullptr;
        if (pi.nonStructType.MapNameOffset) {
            PWCHAR mapName = reinterpret_cast<PWCHAR>(
                reinterpret_cast<BYTE*>(pInfo)
                + pi.nonStructType.MapNameOffset);

            ULONG mapSize = 0;
            TdhGetEventMapInformation(pEvent, mapName, nullptr, &mapSize);
            if (mapSize > 0) {
                pMap = reinterpret_cast<PEVENT_MAP_INFO>(malloc(mapSize));
                if (pMap)
                    TdhGetEventMapInformation(pEvent, mapName, pMap, &mapSize);
            }
        }

        // ── Format the property value ─────────────────────────────────────────
        //    First call: probe for the required buffer size
        ULONG  fmtSize  = 0;
        USHORT consumed = 0;

        ULONG fmtStatus = TdhFormatProperty(
            pInfo,
            pMap,
            sizeof(ULONG_PTR),              // native pointer size
            pi.nonStructType.InType,
            pi.nonStructType.OutType,
            pi.length,                      // 0 = variable-length; TDH resolves it
            userDataLeft,
            pUserData,
            &fmtSize,
            nullptr,
            &consumed
        );

        if (fmtStatus == ERROR_INSUFFICIENT_BUFFER && fmtSize > 0)
        {
            std::vector<WCHAR> valBuf(fmtSize / sizeof(WCHAR) + 1, L'\0');

            fmtStatus = TdhFormatProperty(
                pInfo,
                pMap,
                sizeof(ULONG_PTR),
                pi.nonStructType.InType,
                pi.nonStructType.OutType,
                pi.length,
                userDataLeft,
                pUserData,
                &fmtSize,
                valBuf.data(),
                &consumed
            );

            if (fmtStatus == ERROR_SUCCESS)
            {
                std::wcout << L"    "
                           << std::setw(26) << std::left << propName
                           << L" = " << valBuf.data() << L"\n";
            }
        }

        if (pMap) { free(pMap); pMap = nullptr; }

        // ── Advance UserData pointer ───────────────────────────────────────────
        //    `consumed` is the exact byte count TDH read for this property.
        //    Failing to advance correctly means every subsequent property
        //    decodes from the wrong offset and produces garbage.
        if (consumed > 0 && consumed <= userDataLeft) {
            pUserData    += consumed;
            userDataLeft -= consumed;
        } else {
            break;  // Cannot advance safely — stop property walk
        }
    }

    free(pInfo);
}

// ─── Opcode label ─────────────────────────────────────────────────────────────
//
//  Maps provider GUID + opcode byte to a human-readable action string.
//  The modern manifest-based providers use EventId (not opcode) for
//  discrimination, but many kernel events still surface a meaningful opcode.

static std::wstring OpcodeLabel(const GUID& g, UCHAR opcode)
{
    if (GuidEqual(g, k_ProcessProviderGuid)) {
        switch (opcode) {
            case 1:  return L"ProcessStart   ";
            case 2:  return L"ProcessStop    ";
            case 3:  return L"ThreadStart    ";
            case 4:  return L"ThreadStop     ";
            case 5:  return L"ImageLoad      ";
            case 6:  return L"ImageUnload    ";
            default: return L"ProcessEvent   ";
        }
    }
    if (GuidEqual(g, k_FileProviderGuid)) {
        switch (opcode) {
            case 0:  return L"FileName       ";
            case 32: return L"FileCreate     ";
            case 33: return L"FileCleanup    ";
            case 34: return L"FileClose      ";
            case 35: return L"FileRead       ";
            case 36: return L"FileWrite      ";
            case 37: return L"FileSetInfo    ";
            case 38: return L"FileDelete     ";
            case 39: return L"FileRename     ";
            case 40: return L"FileDirEnum    ";
            case 41: return L"FileFlush      ";
            case 42: return L"FileQueryInfo  ";
            case 64: return L"FileCreateV2   ";
            default: return L"FileEvent      ";
        }
    }
    if (GuidEqual(g, k_RegistryProviderGuid)) {
        switch (opcode) {
            case 1:  return L"RegCreateKey   ";
            case 2:  return L"RegOpenKey     ";
            case 3:  return L"RegDeleteKey   ";
            case 4:  return L"RegQueryKey    ";
            case 5:  return L"RegSetValue    ";
            case 6:  return L"RegDeleteValue ";
            case 7:  return L"RegQueryValue  ";
            case 8:  return L"RegEnumKey     ";
            case 9:  return L"RegEnumValue   ";
            case 12: return L"RegCloseKey    ";
            default: return L"RegEvent       ";
        }
    }
    WCHAR buf[24];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"Opcode%-2u       ",
                 static_cast<UINT>(opcode));
    return buf;
}

// ─── Event filter ─────────────────────────────────────────────────────────────
//
//  We already limited events at the provider level via EnableTraceEx2 keywords,
//  but this gives a second, cheaper gate before we spend time on TDH decoding.

static bool ShouldDecode(PEVENT_RECORD pEvent)
{
    if (pEvent->UserDataLength == 0 || pEvent->UserData == nullptr)
        return false;

    // Suppress Version 0 ProcessStart -- fires before ImageName is resolved.
    // Version 1+ carries the full payload including ImageName, token info,
    // package identity etc. and is the event worth acting on.
    if (GuidEqual(pEvent->EventHeader.ProviderId, k_ProcessProviderGuid) &&
        pEvent->EventHeader.EventDescriptor.Id == 1 &&  // ProcessStart
        pEvent->EventHeader.EventDescriptor.Version == 0)
    {
        return false;
    }

    return true;
}

// ─── Event filter: decide whether to print this event ────────────────────────
//
//  We only decode events from the three kernel providers we care about.
//  Returning false suppresses output for noisy/uninteresting opcodes.

static bool ShouldPrint(PEVENT_RECORD pEvent)
{
    const GUID& g = pEvent->EventHeader.ProviderId;
    UCHAR opcode = pEvent->EventHeader.EventDescriptor.Opcode;

    if (GuidEqual(g, k_ProcessProviderGuid)) {
        return (opcode == PROC_OPCODE_START || opcode == PROC_OPCODE_STOP);
    }
    if (GuidEqual(g, k_FileProviderGuid)) {
        // Suppress the very high-rate read/write opcodes by default.
        // Uncomment the line below to see them:
        //return false;
        return (opcode == FILE_OPCODE_CREATE ||
                opcode == FILE_OPCODE_DELETE  ||
                opcode == FILE_OPCODE_RENAME  ||
                opcode == FILE_OPCODE_MKDIR);
    }
    if (GuidEqual(g, k_RegistryProviderGuid)) {
        return (opcode == REG_OPCODE_CREATE ||
            opcode == REG_OPCODE_OPEN ||
            opcode == REG_OPCODE_SET_VALUE ||
            opcode == REG_OPCODE_DELETE_KEY ||
            opcode == REG_OPCODE_DELETE_VALUE);
    }
    return false;
}

// ─── EventRecord callback ─────────────────────────────────────────────────────
//
//  Invoked by ProcessTrace for every event on the session.
//  Must be WINAPI (stdcall) per the ETW ABI.

static VOID WINAPI EventRecordCallback(PEVENT_RECORD pEvent)
{
    if (!pEvent) return;

    // Filter to our three kernel providers
    if (!ShouldPrint(pEvent)) return;

    const GUID& provGuid = pEvent->EventHeader.ProviderId;

    // Only handle our three providers
    if (!GuidEqual(provGuid, k_ProcessProviderGuid)  &&
        !GuidEqual(provGuid, k_FileProviderGuid)     &&
        !GuidEqual(provGuid, k_RegistryProviderGuid))
        return;

    const UCHAR  opcode  = pEvent->EventHeader.EventDescriptor.Opcode;
    const USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;
    const ULONG  pid     = pEvent->EventHeader.ProcessId;
    const ULONG  tid     = pEvent->EventHeader.ThreadId;

    std::wstring ts     = FormatTimestamp(pEvent->EventHeader.TimeStamp);
    std::wstring label  = ProviderLabel(provGuid);

    {
        std::lock_guard<std::mutex> lk(g_printMtx);

        // ── Header line ───────────────────────────────────────────────────────
        std::wstring action = OpcodeLabel(provGuid, opcode);
        std::wcout
            << L"[" << ts << L"]  "
            << label   << L"  "
            << std::setw(16) << std::left << action
            << L"  EventId=" << std::setw(5)  << std::left << eventId
            << L"  Opcode="  << std::setw(3)  << std::left
                             << static_cast<UINT>(opcode)
            << L"  PID="     << std::setw(7)  << std::left << pid
            << L"  TID="     << std::setw(7)  << std::left << tid
            << L"\n";

        // ── Property block ────────────────────────────────────────────────────
        if (ShouldDecode(pEvent))
            PrintPropertiesTDH(pEvent);

        std::wcout << L"\n";
    }
}

// ─── SESSION: allocate EVENT_TRACE_PROPERTIES ─────────────────────────────────
//
//  The structure must have extra space appended for the session name string.
//  LogFileNameOffset is 0 because we use real-time mode (no file).

static EVENT_TRACE_PROPERTIES* AllocSessionProperties()
{
    const ULONG nameBytes =
        static_cast<ULONG>((wcslen(k_SessionName) + 1) * sizeof(WCHAR));
    const ULONG totalSize = sizeof(EVENT_TRACE_PROPERTIES) + nameBytes;

    auto* p = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(calloc(1, totalSize));
    if (!p) return nullptr;

    // Generate a new random GUID for this private session
    CoCreateGuid(&p->Wnode.Guid);

    p->Wnode.BufferSize    = totalSize;
    p->Wnode.ClientContext  = 1;                      // QPC clock resolution
    p->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;

    p->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    p->BufferSize          = 64;                      // KB per ETW buffer
    p->MinimumBuffers      = 16;
    p->MaximumBuffers      = 64;
    p->FlushTimer          = 1;                       // flush to consumer every 1s

    // EnableFlags intentionally 0 — we use EnableTraceEx2 per provider
    p->EnableFlags         = 0;

    p->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
    p->LogFileNameOffset   = 0;

    wcscpy_s(
        reinterpret_cast<PWCHAR>(reinterpret_cast<BYTE*>(p)
            + p->LoggerNameOffset),
        nameBytes / sizeof(WCHAR),
        k_SessionName);

    return p;
}

// ─── SESSION: start ───────────────────────────────────────────────────────────

static bool StartSession()
{
    auto* p = AllocSessionProperties();
    if (!p) { std::wcerr << L"[!] OOM in AllocSessionProperties\n"; return false; }

    ULONG status = StartTrace(&g_hSession, k_SessionName, p);

    if (status == ERROR_ALREADY_EXISTS) {
        // A stale session with our name exists (e.g. previous crash) -- clean it up
        std::wcout << L"[*] Stale session found -- stopping it...\n";
        auto* pStop = AllocSessionProperties();
        if (pStop) {
            ControlTrace(0, k_SessionName, pStop, EVENT_TRACE_CONTROL_STOP);
            free(pStop);
        }
        Sleep(300);
        // Retry
        auto* pRetry = AllocSessionProperties();
        if (pRetry) {
            status = StartTrace(&g_hSession, k_SessionName, pRetry);
            free(pRetry);
        }
    }

    free(p);

    if (status != ERROR_SUCCESS) {
        std::wcerr << L"[!] StartTrace failed: " << status << L"\n";
        if (status == ERROR_ACCESS_DENIED)
            std::wcerr << L"    -> Run as Administrator.\n";
        return false;
    }

    std::wcout << L"[+] Session started: " << k_SessionName
               << L"  (handle=0x" << std::hex << g_hSession << std::dec << L")\n";
    return true;
}

// ─── PROVIDERS: enable via EnableTraceEx2 ────────────────────────────────────
//
//  EnableTraceEx2 lets you:
//    - target specific event categories via Keywords
//    - set severity filtering via Level
//    - request call-stack capture per event (EVENT_ENABLE_PROPERTY_STACK_TRACE)
//    - filter by PID, TID, or executable name via ENABLE_TRACE_PARAMETERS
//
//  Multiple sessions can enable the same provider simultaneously — no singleton
//  conflict, unlike KERNEL_LOGGER_NAME.

static bool EnableProviders()
{
    struct ProviderSpec {
        const GUID*    guid;
        ULONGLONG      keywords;
        const wchar_t* label;
    };

    // Compose keyword masks for each provider
    const ULONGLONG processKeywords =
        PROC_KW_PROCESS; // |   // ProcessStart, ProcessStop
        //PROC_KW_IMAGE_LOAD;    // DLL/EXE load events (remove if too noisy)

    const ULONGLONG fileKeywords =
        FILE_KW_CREATE     |
        FILE_KW_CLOSE      |
        FILE_KW_DELETE     |
        FILE_KW_RENAME     |
        FILE_KW_SET_INFO   |
        FILE_KW_NAME;          // filename-resolution events
        // Omit FILE_KW_READ / FILE_KW_WRITE to avoid extremely high event rates.
        // Add them back only when specifically needed.

    const ULONGLONG registryKeywords =
        REG_KW_CREATE_KEY   |   // RegCreateKey
        REG_KW_SET_VALUE    |   // RegSetValue
        REG_KW_DELETE_KEY   |   // RegDeleteKey
        REG_KW_DELETE_VALUE;    // RegDeleteValue
        // REG_KW_OPEN_KEY and REG_KW_QUERY_VALUE omitted -- extremely noisy
        // on a live system; every app opening HKLM\Software fires them.

    ProviderSpec providers[] = {
        { &k_ProcessProviderGuid,  processKeywords,  L"Kernel-Process"  },
        { &k_FileProviderGuid,     fileKeywords,     L"Kernel-File"     },
        { &k_RegistryProviderGuid, registryKeywords, L"Kernel-Registry" },
    };

    for (auto& prov : providers)
    {
        ENABLE_TRACE_PARAMETERS params = {};
        params.Version        = ENABLE_TRACE_PARAMETERS_VERSION_2;

        // Optional: request call stacks for every event.
        // Useful for attribution but adds overhead; comment out if not needed.
        params.EnableProperty = EVENT_ENABLE_PROPERTY_STACK_TRACE;

        ULONG status = EnableTraceEx2(
            g_hSession,
            prov.guid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE,    // capture all severity levels
            prov.keywords,
            0,                      // MatchAllKeyword mask (0 = not used)
            0,                      // Timeout ms (0 = asynchronous)
            &params
        );

        if (status != ERROR_SUCCESS) {
            std::wcerr << L"[!] EnableTraceEx2 failed for "
                       << prov.label << L": " << status << L"\n";
            return false;
        }
        std::wcout << L"[+] Enabled: " << prov.label
                   << L"  (keywords=0x" << std::hex << prov.keywords
                   << std::dec << L")\n";
    }
    return true;
}

// ─── CONSUMER: open and process ───────────────────────────────────────────────

static bool OpenAndProcess()
{
    EVENT_TRACE_LOGFILE lf      = {};
    lf.LoggerName               = const_cast<LPWSTR>(k_SessionName);
    lf.ProcessTraceMode         = PROCESS_TRACE_MODE_REAL_TIME |
                                  PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback      = EventRecordCallback;

    g_hTrace = OpenTrace(&lf);
    if (g_hTrace == INVALID_PROCESSTRACE_HANDLE) {
        std::wcerr << L"[!] OpenTrace failed: " << GetLastError() << L"\n";
        return false;
    }

    std::wcout << L"\n[+] Consuming events (Ctrl+C to stop)...\n";
    std::wcout << std::wstring(80, L'-') << L"\n\n";

    // ProcessTrace blocks until StopTrace / CloseTrace is called.
    // It is intentionally run on a background thread (see wmain).
    ULONG status = ProcessTrace(&g_hTrace, 1, nullptr, nullptr);

    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
        std::wcerr << L"[!] ProcessTrace ended: " << status << L"\n";

    return true;
}

// ─── CLEANUP ──────────────────────────────────────────────────────────────────

static void Shutdown()
{
    // 1. Disable all providers gracefully
    const GUID* provGuids[] = {
        &k_ProcessProviderGuid,
        &k_FileProviderGuid,
        &k_RegistryProviderGuid,
    };
    for (auto* g : provGuids) {
        EnableTraceEx2(g_hSession, g,
            EVENT_CONTROL_CODE_DISABLE_PROVIDER,
            0, 0, 0, 0, nullptr);
    }

    // 2. Unblock ProcessTrace
    if (g_hTrace != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_hTrace);
        g_hTrace = INVALID_PROCESSTRACE_HANDLE;
    }

    // 3. Stop the controller session
    if (g_hSession != INVALID_PROCESSTRACE_HANDLE) {
        auto* p = AllocSessionProperties();
        if (p) {
            ControlTrace(g_hSession, k_SessionName, p, EVENT_TRACE_CONTROL_STOP);
            free(p);
        }
        g_hSession = INVALID_PROCESSTRACE_HANDLE;
        std::wcout << L"\n[*] Session stopped.\n";
    }
}

// ─── Ctrl+C handler ───────────────────────────────────────────────────────────

static BOOL WINAPI CtrlHandler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) {
        std::wcout << L"\n[*] Ctrl+C -- shutting down...\n";
        g_running = false;
        Shutdown();
        return TRUE;
    }
    return FALSE;
}

// ─── Entry point ──────────────────────────────────────────────────────────────

int wmain()
{
    // Fix 1: set stdout/stderr to UTF-16 mode BEFORE any wcout call.
    // This lets wcout handle the full Unicode range (em dashes, file paths,
    // registry key names etc.) without stream-poisoning on codepage conversion.
    // Once set, do NOT mix narrow printf / std::cout on the same handle.
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);

    std::wcout << L"ETW Kernel Monitor -- Process / File I/O / Registry\n";
    std::wcout << std::wstring(80, L'=') << L"\n\n";

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    // Start the private ETW controller session
    if (!StartSession())  return 1;

    // Enable kernel providers individually via EnableTraceEx2
    if (!EnableProviders()) { Shutdown(); return 1; }

    // Run the blocking ProcessTrace call on a background thread
    std::thread traceThread([]() { OpenAndProcess(); });

    // Main thread: spin until Ctrl+C or trace ends
    while (g_running) Sleep(250);

    // Ensure cleanup if we exited the loop without Ctrl+C
    Shutdown();

    if (traceThread.joinable()) traceThread.join();

    std::wcout << L"[+] Done.\n";
    return 0;
}

// ─── Architecture notes ───────────────────────────────────────────────────────
//
//  Custom session vs KERNEL_LOGGER_NAME
//  -------------------------------------
//  KERNEL_LOGGER_NAME is a system singleton -- only one owner at a time.
//  A custom session name allows multiple security tools, diagnostic tools and
//  our own session to coexist without evicting each other.
//
//  EnableTraceEx2 advantages over EnableFlags
//  -------------------------------------------
//  - Per-provider keyword masks: enables exactly the event categories needed.
//  - Per-provider level: TRACE_LEVEL_INFORMATION reduces noise vs VERBOSE.
//  - Stack-trace capture: EVENT_ENABLE_PROPERTY_STACK_TRACE gives call stacks
//    per event, invaluable for attribution and detection chain reconstruction.
//  - Hot-path control: providers can be enabled/disabled mid-session without
//    restarting, allowing adaptive telemetry volume control at runtime.
//  - PID/TID filtering: ENABLE_TRACE_PARAMETERS supports EVENT_FILTER_DESCRIPTOR
//    to restrict capture to specific processes -- critical for high-rate providers
//    like File I/O where system-wide capture is impractical in production.
//
//  FILE_KW_READ / FILE_KW_WRITE
//  ----------------------------
//  Intentionally excluded from the default keyword mask.  On a busy system
//  these can generate millions of events per second, saturating ETW buffers
//  and causing event loss.  Enable them only with a PID filter in place.
//
//  TDH UserData pointer tracking
//  ------------------------------
//  TdhFormatProperty returns the number of bytes it consumed via the `consumed`
//  out-parameter.  The caller MUST advance the UserData pointer by exactly that
//  amount before the next property call.  Failure to do so causes all subsequent
//  properties to decode garbage from the wrong buffer offset.
//
//  Production hardening checklist
//  --------------------------------
//  - Implement BufferCallback on EVENT_TRACE_LOGFILE to monitor buffer-drop
//    counts (EventsLost) and emit telemetry when events are being dropped.
//  - Build a PID->ImageFileName map from ProcessStart events so subsequent
//    File/Registry events can be annotated with the originating process name.
//  - Add EVENT_FILTER_DESCRIPTOR with an executable path filter to the
//    ENABLE_TRACE_PARAMETERS for File I/O to suppress high-rate system noise.
//  - Use PROCESS_TRACE_MODE_RAW_TIMESTAMP with a separate timestamp conversion
//    step if sub-millisecond latency attribution is required.
