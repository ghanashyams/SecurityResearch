#!/usr/bin/env python3
"""
inject_test.py -- benign CreateRemoteThread PoC for testing remote_thread_detect.cpp

Spawns (or attaches to) a target process on THIS machine and performs a
classic CreateRemoteThread injection into it, using only harmless payloads,
so the krabs-based detector (remote_thread_detect.cpp) has something real
to catch. Intended for local, authorized testing of your own detection
tool only -- do not point this at a process you don't own/control.

Two modes:

  loadlibrary (default, safest)
      CreateRemoteThread's start routine is kernel32.dll!LoadLibraryA,
      with the argument pointing at the path of an already-loaded, inert
      system DLL. This is the classic "remote LoadLibrary" injection
      technique, but the payload is just "load a DLL that's already
      loaded" (a harmless refcount bump). In the detector's output,
      Win32StartAddr should resolve to something like
      "...\\System32\\kernel32.dll+0xOFFSET" -- a normal module hit.

  shellcode
      Allocates a tiny RWX region in the target and writes a 3-byte inert
      stub (`xor eax, eax; ret` -- returns 0 and does nothing else), then
      starts the remote thread there instead of in a real module. This is
      the shape of genuine shellcode injection. In the detector's output,
      Win32StartAddr should resolve to
      "<UNBACKED -- not inside any known loaded module (possible injected code)>".

Usage:
    python inject_test.py                          # spawn notepad.exe, LoadLibraryA mode
    python inject_test.py --mode shellcode          # spawn notepad.exe, inert-shellcode mode
    python inject_test.py --pid 12345 --mode shellcode
    python inject_test.py --target-exe "C:\\Windows\\System32\\notepad.exe"

Requirements:
    - Windows, 64-bit Python (must match the target process's bitness).
    - Run the detector (remote_thread_detect.cpp, as Administrator) in a
      separate terminal first, then run this script.
"""

import argparse
import ctypes
import os
import subprocess
import sys
import time
from ctypes import wintypes

if os.name != "nt":
    sys.exit("This script only runs on Windows.")

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# --- constants ---------------------------------------------------------

PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
STILL_ACTIVE = 259

# --- ctypes signatures ---------------------------------------------------

kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)

kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)

kernel32.VirtualAllocEx.restype = wintypes.LPVOID
kernel32.VirtualAllocEx.argtypes = (
    wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD,
)

kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = (
    wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
)

kernel32.CreateRemoteThread.restype = wintypes.HANDLE
kernel32.CreateRemoteThread.argtypes = (
    wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID,
    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
)

kernel32.GetModuleHandleW.restype = wintypes.HMODULE
kernel32.GetModuleHandleW.argtypes = (wintypes.LPCWSTR,)

kernel32.GetProcAddress.restype = wintypes.LPVOID
kernel32.GetProcAddress.argtypes = (wintypes.HMODULE, ctypes.c_char_p)

kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)

kernel32.GetExitCodeProcess.restype = wintypes.BOOL
kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))

kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlpcsBase", wintypes.LPVOID),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * 260),
    ]


kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32FirstW.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))

kernel32.Process32NextW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))

kernel32.Module32FirstW.restype = wintypes.BOOL
kernel32.Module32FirstW.argtypes = (wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W))

kernel32.Module32NextW.restype = wintypes.BOOL
kernel32.Module32NextW.argtypes = (wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W))


# --- process discovery -----------------------------------------------------

def list_pids_by_name(exe_name):
    exe_name_lower = exe_name.lower()
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == -1 or snapshot == 0:
        raise ctypes.WinError(ctypes.get_last_error())

    pids = set()
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

    try:
        found = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while found:
            if entry.szExeFile.lower() == exe_name_lower:
                pids.add(entry.th32ProcessID)
            found = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)

    return pids


def is_process_alive(pid):
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return False
    try:
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return False
        return exit_code.value == STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def get_module_base_in_process(pid, module_name, max_retries=10):
    """
    Get the base address of a DLL loaded in a target process.
    Retries multiple times since processes need time to load their modules.
    Returns the base address or None if not found.
    """
    module_name_lower = module_name.lower()

    for attempt in range(max_retries):
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
        if snapshot == -1 or snapshot == 0:
            time.sleep(0.1)
            continue

        try:
            entry = MODULEENTRY32W()
            entry.dwSize = ctypes.sizeof(MODULEENTRY32W)

            if not kernel32.Module32FirstW(snapshot, ctypes.byref(entry)):
                time.sleep(0.1)
                continue

            while True:
                if entry.szModule.lower() == module_name_lower:
                    base = ctypes.cast(entry.GlpcsBase, ctypes.c_void_p).value
                    print(f"[*] Found {module_name} at 0x{base:x} (attempt {attempt + 1}/{max_retries})")
                    return base
                if not kernel32.Module32NextW(snapshot, ctypes.byref(entry)):
                    break
        finally:
            kernel32.CloseHandle(snapshot)

        time.sleep(0.1)

    return None


def spawn_and_find_pid(exe_path, settle_seconds=2.0):
    """Spawns exe_path and returns the PID of the process that's actually
    still running afterward. Handles Windows 11's notepad.exe sometimes
    being a launcher stub that hands off to a differently-PID'd host
    process by diffing the process list by image name before/after."""
    exe_name = os.path.basename(exe_path)
    before = list_pids_by_name(exe_name)

    proc = subprocess.Popen([exe_path])
    time.sleep(settle_seconds)

    after = list_pids_by_name(exe_name)
    candidates = {pid for pid in (after - before) if is_process_alive(pid)}

    if not candidates and is_process_alive(proc.pid):
        candidates = {proc.pid}

    if len(candidates) != 1:
        raise RuntimeError(
            f"Could not uniquely identify the spawned {exe_name} process "
            f"(candidates: {candidates or 'none'}). Pass --pid explicitly instead."
        )

    return candidates.pop()


# --- injection -----------------------------------------------------------

def inject_loadlibrary(pid, dll_path):
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        path_bytes = (dll_path + "\0").encode("mbcs")
        remote_addr = kernel32.VirtualAllocEx(
            h_process, None, len(path_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        )
        if not remote_addr:
            raise ctypes.WinError(ctypes.get_last_error())

        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(
            h_process, remote_addr, path_bytes, len(path_bytes), ctypes.byref(written)
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
        load_library_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")
        if not load_library_addr:
            raise ctypes.WinError(ctypes.get_last_error())

        thread_id = wintypes.DWORD(0)
        h_thread = kernel32.CreateRemoteThread(
            h_process, None, 0, load_library_addr, remote_addr, 0, ctypes.byref(thread_id)
        )
        if not h_thread:
            raise ctypes.WinError(ctypes.get_last_error())

        print(f"[+] CreateRemoteThread OK: target PID={pid}, remote TID={thread_id.value}, "
              f"start=kernel32!LoadLibraryA, arg={dll_path!r}")

        kernel32.WaitForSingleObject(h_thread, 5000)
        kernel32.CloseHandle(h_thread)
    finally:
        kernel32.CloseHandle(h_process)


def inject_shellcode(pid):
    # xor eax, eax ; ret -- returns 0 and does nothing else. Inert on purpose.
    stub = bytes([0x33, 0xC0, 0xC3])

    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        remote_addr = kernel32.VirtualAllocEx(
            h_process, None, len(stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        )
        if not remote_addr:
            raise ctypes.WinError(ctypes.get_last_error())

        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(
            h_process, remote_addr, stub, len(stub), ctypes.byref(written)
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        thread_id = wintypes.DWORD(0)
        h_thread = kernel32.CreateRemoteThread(
            h_process, None, 0, remote_addr, None, 0, ctypes.byref(thread_id)
        )
        if not h_thread:
            raise ctypes.WinError(ctypes.get_last_error())

        print(f"[+] CreateRemoteThread OK: target PID={pid}, remote TID={thread_id.value}, "
              f"start=0x{remote_addr:x} (private RWX stub, 3 bytes, inert)")

        kernel32.WaitForSingleObject(h_thread, 5000)
        kernel32.CloseHandle(h_thread)
    finally:
        kernel32.CloseHandle(h_process)


def inject_test_diagnostic(pid):
    """
    Diagnostic test: write a marker value to a known memory location.
    This verifies shellcode execution without needing complex API calls.
    """
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        print("[*] Diagnostic test: injecting simple memory marker")

        # Allocate a test area where we'll write a marker
        test_addr = kernel32.VirtualAllocEx(
            h_process, None, 256, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        )
        if not test_addr:
            raise ctypes.WinError(ctypes.get_last_error())

        # x64 shellcode that writes 0xDEADBEEF to the test area
        # mov rax, test_addr
        # mov dword [rax], 0xDEADBEEF
        # ret
        shellcode = bytearray()
        shellcode += bytes([0x48, 0xB8]) + (test_addr).to_bytes(8, 'little')  # mov rax, test_addr
        shellcode += bytes([0xC7, 0x00, 0xEF, 0xBE, 0xAD, 0xDE])  # mov dword [rax], 0xDEADBEEF
        shellcode += bytes([0xC3])  # ret

        # Allocate shellcode
        shellcode_addr = kernel32.VirtualAllocEx(
            h_process, None, len(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        )
        if not shellcode_addr:
            raise ctypes.WinError(ctypes.get_last_error())

        # Write shellcode
        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(h_process, shellcode_addr, bytes(shellcode), len(shellcode), ctypes.byref(written)):
            raise ctypes.WinError(ctypes.get_last_error())

        # Create remote thread
        thread_id = wintypes.DWORD(0)
        h_thread = kernel32.CreateRemoteThread(
            h_process, None, 0, shellcode_addr, None, 0, ctypes.byref(thread_id)
        )
        if not h_thread:
            raise ctypes.WinError(ctypes.get_last_error())

        print(f"[+] Shellcode injected at 0x{shellcode_addr:x}")
        print(f"[+] Test marker location: 0x{test_addr:x}")
        print(f"[+] Waiting for thread to execute...")

        kernel32.WaitForSingleObject(h_thread, 5000)
        kernel32.CloseHandle(h_thread)

        # Read back the test area to verify execution
        test_value = ctypes.c_uint32(0)
        bytes_read = ctypes.c_size_t(0)
        if kernel32.ReadProcessMemory(
            h_process, ctypes.c_void_p(test_addr), ctypes.byref(test_value), 4, ctypes.byref(bytes_read)
        ):
            if test_value.value == 0xDEADBEEF:
                print("[+] SUCCESS! Shellcode executed and wrote marker (0xDEADBEEF)")
            else:
                print(f"[!] Marker not found. Read value: 0x{test_value.value:x}")
        else:
            print("[!] Could not read test area")

    finally:
        kernel32.CloseHandle(h_process)


def inject_messagebox(pid):
    """
    Inject shellcode that calls ExitProcess(0) in the target process.
    If this works, notepad will close — proving function invocation works.
    Then we can debug WinExec separately.
    """
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        # Get ExitProcess address from kernel32 in our process
        h_kernel32_local = kernel32.GetModuleHandleW("kernel32.dll")
        exitprocess_offset = kernel32.GetProcAddress(h_kernel32_local, b"ExitProcess")
        if not exitprocess_offset:
            raise ctypes.WinError(ctypes.get_last_error())

        # Get kernel32 base in our process
        kernel32_base_local = ctypes.cast(h_kernel32_local, ctypes.c_void_p).value
        exitprocess_rva = ctypes.cast(exitprocess_offset, ctypes.c_void_p).value - kernel32_base_local

        # Query the actual kernel32 base in the TARGET process (accounts for ASLR)
        print("[*] Waiting for target to load kernel32...")
        time.sleep(0.5)
        kernel32_base_target = get_module_base_in_process(pid, "kernel32.dll", max_retries=10)
        if not kernel32_base_target:
            print("[!] Warning: Could not find kernel32 in target, assuming same base")
            kernel32_base_target = kernel32_base_local

        exitprocess_addr = kernel32_base_target + exitprocess_rva

        print(f"[*] kernel32.dll local base: 0x{kernel32_base_local:x}")
        print(f"[*] kernel32.dll target base: 0x{kernel32_base_target:x}")
        print(f"[*] ExitProcess RVA: 0x{exitprocess_rva:x}")
        print(f"[*] ExitProcess address in target: 0x{exitprocess_addr:x}")

        # x64 shellcode that calls ExitProcess(0)
        # Must set up stack properly for x64 calling convention (32-byte shadow space)
        shellcode = bytearray()
        shellcode += bytes([0x48, 0x83, 0xEC, 0x28])  # sub rsp, 0x28 (allocate shadow space + alignment)
        shellcode += bytes([0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00])  # mov rcx, 0
        shellcode += bytes([0x48, 0xB8]) + (exitprocess_addr).to_bytes(8, 'little')  # mov rax, exitprocess_addr
        shellcode += bytes([0xFF, 0xD0])  # call rax
        # (ExitProcess won't return, but if it did, we'd need: add rsp, 0x28; ret)

        # Allocate shellcode in target with RWX permissions
        shellcode_addr = kernel32.VirtualAllocEx(
            h_process, None, len(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        )
        if not shellcode_addr:
            raise ctypes.WinError(ctypes.get_last_error())

        # Write shellcode to target process
        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(h_process, shellcode_addr, bytes(shellcode), len(shellcode), ctypes.byref(written)):
            raise ctypes.WinError(ctypes.get_last_error())

        # Create remote thread to execute shellcode
        thread_id = wintypes.DWORD(0)
        h_thread = kernel32.CreateRemoteThread(
            h_process, None, 0, shellcode_addr, None, 0, ctypes.byref(thread_id)
        )
        if not h_thread:
            raise ctypes.WinError(ctypes.get_last_error())

        print(f"[+] CreateRemoteThread OK: target PID={pid}, remote TID={thread_id.value}")
        print(f"[+] Shellcode start: 0x{shellcode_addr:x} ({len(shellcode)} bytes)")
        print(f"[+] Calling ExitProcess(0) to terminate notepad...")
        print(f"[+] If notepad closes, function invocation works!")

        wait_result = kernel32.WaitForSingleObject(h_thread, 5000)
        print(f"[*] Thread wait result: {wait_result} (0=signaled, 258=timeout)")

        # Check thread exit code
        exit_code = wintypes.DWORD(0)
        if kernel32.GetExitCodeThread(h_thread, ctypes.byref(exit_code)):
            print(f"[*] Thread exit code: 0x{exit_code.value:x}")
            if exit_code.value == 259:  # STILL_ACTIVE
                print("[!] Thread is still running (didn't exit)")
            else:
                print(f"[+] Thread exited with code 0x{exit_code.value:x}")
        else:
            print("[!] Could not get thread exit code")

        kernel32.CloseHandle(h_thread)
    finally:
        kernel32.CloseHandle(h_process)


# --- main ------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Benign CreateRemoteThread PoC for testing remote_thread_detect.cpp"
    )
    parser.add_argument("--pid", type=int, default=None,
                         help="Target an existing process instead of spawning one")
    parser.add_argument("--target-exe", default=r"C:\Windows\System32\notepad.exe",
                         help="Executable to spawn as the injection target (default: notepad.exe)")
    parser.add_argument("--mode", choices=["loadlibrary", "shellcode", "messagebox", "test"], default="loadlibrary",
                         help="loadlibrary (default): CreateRemoteThread->LoadLibraryA, "
                              "should resolve to a known module in the detector. "
                              "shellcode: inert stub in private memory, should show as UNBACKED. "
                              "messagebox: spawn calc.exe via WinExec in target. "
                              "test: simple diagnostic (creates C:\\test_injection.txt).")
    parser.add_argument("--dll", default=r"C:\Windows\System32\version.dll",
                         help="DLL to LoadLibraryA in loadlibrary mode -- any harmless, "
                              "already-present system DLL works")
    args = parser.parse_args()

    if args.pid is not None:
        pid = args.pid
        print(f"[*] Targeting existing PID {pid}")
    else:
        print(f"[*] Spawning {args.target_exe} ...")
        pid = spawn_and_find_pid(args.target_exe)
        print(f"[*] Target PID: {pid}")

    if args.mode == "loadlibrary":
        inject_loadlibrary(pid, args.dll)
    elif args.mode == "shellcode":
        inject_shellcode(pid)
    elif args.mode == "messagebox":
        inject_messagebox(pid)
    else:  # test
        inject_test_diagnostic(pid)

    print("[*] Done. Check the detector's output for the corresponding "
          "\"[!] Remote thread created\" entry.")


if __name__ == "__main__":
    main()
