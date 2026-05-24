#pragma once
#include "utils.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#pragma comment(lib, "psapi.lib")

// ─── Enable SeDebugPrivilege so we can open protected processes ───────────────
inline bool EnableDebugPrivilege() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return ok;
}

struct ProcessEntry {
    DWORD  pid;
    std::string name;
    std::string path;
    SIZE_T memKB;
    bool   isSuspicious;
};

// Простая эвристика — имена процессов, часто встречающихся у малвари
static const std::vector<std::string> kSuspiciousNames = {
    "cryptominer","miner","keylog","trojan","spyware","adware",
    "inject","hook","rat.exe","stealer","banker","ransom",
    "payload","loader","dropper"
};

inline bool IsSuspiciousName(const std::string& name) {
    std::string low = name;
    std::transform(low.begin(), low.end(), low.begin(), ::tolower);
    for (auto& s : kSuspiciousNames)
        if (low.find(s) != std::string::npos) return true;
    return false;
}

inline std::vector<ProcessEntry> ListProcesses() {
    std::vector<ProcessEntry> list;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return list;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcessEntry entry{};
            entry.pid  = pe.th32ProcessID;
            entry.name = w2s(pe.szExeFile);

            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProc) {
                wchar_t path[MAX_PATH]{};
                if (GetModuleFileNameExW(hProc, NULL, path, MAX_PATH))
                    entry.path = w2s(path);
                PROCESS_MEMORY_COUNTERS pmc{};
                if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc)))
                    entry.memKB = pmc.WorkingSetSize / 1024;
                CloseHandle(hProc);
            }
            entry.isSuspicious = IsSuspiciousName(entry.name);
            list.push_back(entry);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    // sort by pid
    std::sort(list.begin(), list.end(), [](auto& a, auto& b){ return a.pid < b.pid; });
    return list;
}

inline void TaskManagerMenu() {
    EnableDebugPrivilege();

    while (true) {
        PrintHeader();
        PrintTitle("1. Task Manager");

        auto procs = ListProcesses();

        // Header row
        SetColor(DARK_CYAN);
        std::cout << "  " << std::left
            << std::setw(7)  << "PID"
            << std::setw(32) << "Name"
            << std::setw(10) << "Mem(KB)"
            << "Path\n";
        SetColor(DARK_GRAY);
        std::cout << "  " << std::string(80, '-') << "\n";
        ResetColor();

        for (auto& p : procs) {
            if (p.isSuspicious) SetColor(RED);
            else SetColor(GRAY);

            std::cout << "  "
                << std::left << std::setw(7)  << p.pid
                << std::setw(32) << (p.name.size() > 31 ? p.name.substr(0,28)+"..." : p.name)
                << std::setw(10) << p.memKB
                << (p.path.size() > 50 ? "..."+p.path.substr(p.path.size()-47) : p.path)
                << "\n";
        }
        ResetColor();

        SetColor(DARK_GRAY);
        std::cout << "\n  " << std::string(80, '-') << "\n";
        ResetColor();
        SetColor(YELLOW);
        std::cout << "  [K] Kill by PID   [N] Kill by Name   [S] Show suspicious only   [R] Refresh   [0] Back\n";
        ResetColor();

        std::string cmd = InputLine("Command");
        if (cmd == "0" || cmd == "q" || cmd == "Q") break;

        if (cmd == "R" || cmd == "r") continue;

        if (cmd == "S" || cmd == "s") {
            PrintHeader();
            PrintTitle("Suspicious Processes");
            bool found = false;
            for (auto& p : procs) {
                if (p.isSuspicious) {
                    SetColor(RED);
                    std::cout << "  PID " << p.pid << "  " << p.name << "\n      " << p.path << "\n";
                    ResetColor();
                    found = true;
                }
            }
            if (!found) PrintOK("No suspicious processes found by name heuristic.");
            Pause();
            continue;
        }

        if (cmd == "K" || cmd == "k") {
            int pid = InputInt("Enter PID to kill");
            if (pid <= 0) { PrintErr("Invalid PID."); Pause(); continue; }
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
            if (!h) { PrintErr("Cannot open process (access denied or not found)."); Pause(); continue; }
            if (TerminateProcess(h, 1)) PrintOK("Process " + std::to_string(pid) + " terminated.");
            else PrintErr("Failed to terminate process.");
            CloseHandle(h);
            Pause();
            continue;
        }

        if (cmd == "N" || cmd == "n") {
            std::string name = InputLine("Enter process name (e.g. malware.exe)");
            int killed = 0;
            for (auto& p : procs) {
                std::string plow = p.name, nlow = name;
                std::transform(plow.begin(), plow.end(), plow.begin(), ::tolower);
                std::transform(nlow.begin(), nlow.end(), nlow.begin(), ::tolower);
                if (plow == nlow) {
                    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, p.pid);
                    if (h) { TerminateProcess(h, 1); CloseHandle(h); killed++; }
                }
            }
            if (killed) PrintOK("Killed " + std::to_string(killed) + " process(es) named \"" + name + "\".");
            else PrintErr("No process found with that name.");
            Pause();
        }
    }
}
