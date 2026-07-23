import ctypes
from ctypes import wintypes
import psutil
import win32gui
import win32process

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

def is_process_gui_visible(pid):
    """Checks if the target process owns any visible top-level windows."""
    def enum_windows_callback(hwnd, extra):
        if win32gui.IsWindowVisible(hwnd):
            _, win_pid = win32process.GetWindowThreadProcessId(hwnd)
            if win_pid == extra["pid"]:
                extra["visible"] = True
    
    extra = {"pid": pid, "visible": False}
    try:
        win32gui.EnumWindows(enum_windows_callback, extra)
    except Exception:
        pass
    return extra["visible"]

def get_loaded_modules(pid):
    """Inspects the loaded DLL modules of a process safely on 32-bit and 64-bit systems."""
    modules = []
    
    psapi.GetModuleBaseNameA.argtypes = [
        wintypes.HANDLE, 
        wintypes.HMODULE, 
        ctypes.c_char_p, 
        wintypes.DWORD
    ]
    psapi.GetModuleBaseNameA.restype = wintypes.DWORD

    psapi.EnumProcessModules.argtypes = [
        wintypes.HANDLE, 
        ctypes.POINTER(wintypes.HMODULE), 
        wintypes.DWORD, 
        ctypes.POINTER(wintypes.DWORD)
    ]
    psapi.EnumProcessModules.restype = wintypes.BOOL

    h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    
    if not h_process:
        return modules

    try:
        h_mods = (wintypes.HMODULE * 1024)()
        cb_needed = wintypes.DWORD()
        
        if psapi.EnumProcessModules(h_process, h_mods, ctypes.sizeof(h_mods), ctypes.byref(cb_needed)):
            count = int(cb_needed.value / ctypes.sizeof(wintypes.HMODULE))
            for i in range(min(count, 1024)):
                mod_name = ctypes.create_string_buffer(260)
                if psapi.GetModuleBaseNameA(h_process, h_mods[i], mod_name, ctypes.sizeof(mod_name)):
                    modules.append(mod_name.value.decode('utf-8', errors='ignore').lower())
    except Exception:
        pass
    finally:
        kernel32.CloseHandle(h_process)
        
    return modules

def analyze_process_behavior(proc):
    """Performs behavioral analysis and heuristic checks on a process."""
    score = 0
    reasons = []

    try:
        pid = proc.info['pid']
        name = proc.info['name']
        cmdline = proc.info['cmdline'] or []
        cmd_str = " ".join(cmdline).lower()

        if pid <= 4 or "detector.py" in cmd_str:
            return None

        has_gui = is_process_gui_visible(pid)
        if not has_gui:
            score += 15
            reasons.append("Runs silently in the background (No visible window)")

        loaded_modules = get_loaded_modules(pid)
        hooking_indicators = ['pynput', 'pyhook', 'keyboard', 'user32.dll']
        matched_modules = [m for m in loaded_modules if any(ind in m for ind in hooking_indicators)]
        
        if any(ind in cmd_str for ind in ['pynput', 'keyboard', 'pyhook', 'hook']):
            score += 40
            reasons.append("Command line references keyboard hook libraries")

        try:
            io_counters = proc.io_counters()
            if not has_gui and io_counters.write_bytes > 500_000:
                score += 25
                reasons.append(f"High background disk writes ({io_counters.write_bytes / 1024:.1f} KB logged)")
        except (psutil.AccessDenied, AttributeError):
            pass

        try:
            connections = proc.net_connections(kind='inet')
            if connections and not has_gui:
                score += 20
                reasons.append(f"Background process has active network connection(s) ({len(connections)})")
        except (psutil.AccessDenied, AttributeError):
            pass

        if score >= 35:
            return {
                "pid": pid,
                "name": name,
                "score": score,
                "reasons": reasons,
                "cmd": cmd_str
            }

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    return None

def run_behavioral_scan():
    print("=" * 60)
    print(" 🛡️ ADVANCED BEHAVIORAL & ANTI-HOOKING DETECTOR ")
    print("=" * 60)

    suspicious_processes = []

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        result = analyze_process_behavior(proc)
        if result:
            suspicious_processes.append(result)

    if suspicious_processes:
        print(f"\n⚠️  [ALERT] Detected {len(suspicious_processes)} high-risk process(es):\n")
        for p in suspicious_processes:
            print(f"  📌 Process Name : {p['name']}")
            print(f"  🆔 PID          : {p['pid']}")
            print(f"  ⚠️  Risk Score   : {p['score']}/100")
            print(f"  🔍 Flags        :")
            for reason in p['reasons']:
                print(f"      - {reason}")
            print(f"  💻 Command Line : {p['cmd']}")
            print("-" * 60)
    else:
        print("\n✅ System Clean: No suspicious hooking or background monitoring behaviors detected.")
        print("=" * 60)

if __name__ == "__main__":
    run_behavioral_scan()
