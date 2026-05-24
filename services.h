#pragma once
#include "utils.h"
#include <vector>
#pragma comment(lib, "advapi32.lib")

struct ServiceEntry {
    std::string name;
    std::string displayName;
    std::string status;   // Running, Stopped, etc.
    std::string startType; // Auto, Manual, Disabled
    bool        isSuspicious;
};

// Known malicious or rogue service name fragments
static const std::vector<std::string> kSuspiciousSvcNames = {
    "cryptominer","miner","keylog","rat","spyware","trojan",
    "backdoor","stealer","inject","ransom","payload"
};

inline bool IsSuspiciousSvc(const std::string& name, const std::string& display) {
    auto check = [](const std::string& s, const std::string& kw) {
        std::string sl = s; std::transform(sl.begin(), sl.end(), sl.begin(), ::tolower);
        return sl.find(kw) != std::string::npos;
    };
    for (auto& kw : kSuspiciousSvcNames)
        if (check(name, kw) || check(display, kw)) return true;
    return false;
}

inline std::string SvcStateStr(DWORD state) {
    switch (state) {
        case SERVICE_RUNNING:       return "Running";
        case SERVICE_STOPPED:       return "Stopped";
        case SERVICE_PAUSED:        return "Paused";
        case SERVICE_START_PENDING: return "Starting";
        case SERVICE_STOP_PENDING:  return "Stopping";
        default: return "Unknown";
    }
}
inline std::string SvcStartStr(DWORD type) {
    switch (type) {
        case SERVICE_AUTO_START:     return "Auto";
        case SERVICE_DEMAND_START:   return "Manual";
        case SERVICE_DISABLED:       return "Disabled";
        case SERVICE_BOOT_START:     return "Boot";
        case SERVICE_SYSTEM_START:   return "System";
        default: return "?";
    }
}

inline std::vector<ServiceEntry> ListServices() {
    std::vector<ServiceEntry> list;
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return list;

    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0, &needed, &count, &resume, NULL);

    std::vector<BYTE> buf(needed);
    resume = 0;
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, buf.data(), needed, &needed, &count, &resume, NULL)) {
        CloseServiceHandle(scm);
        return list;
    }

    auto* entries = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
    for (DWORD i = 0; i < count; i++) {
        ServiceEntry e;
        e.name        = w2s(entries[i].lpServiceName);
        e.displayName = w2s(entries[i].lpDisplayName);
        e.status      = SvcStateStr(entries[i].ServiceStatusProcess.dwCurrentState);

        // Get start type
        SC_HANDLE svc = OpenServiceW(scm, entries[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (svc) {
            DWORD cb = 0;
            QueryServiceConfigW(svc, NULL, 0, &cb);
            std::vector<BYTE> cfg(cb);
            auto* qsc = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfg.data());
            if (QueryServiceConfigW(svc, qsc, cb, &cb))
                e.startType = SvcStartStr(qsc->dwStartType);
            CloseServiceHandle(svc);
        }
        e.isSuspicious = IsSuspiciousSvc(e.name, e.displayName);
        list.push_back(e);
    }
    CloseServiceHandle(scm);
    return list;
}

inline bool ControlService_(const std::string& name, DWORD control, DWORD desired) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, s2w(name).c_str(), SERVICE_ALL_ACCESS);
    if (!svc) { CloseServiceHandle(scm); return false; }

    bool ok = false;
    if (control == 0) {
        // Start
        ok = StartServiceW(svc, 0, NULL) != 0;
    } else {
        SERVICE_STATUS ss{};
        ok = ::ControlService(svc, control, &ss) != 0;
    }
    // Set start type if disable requested
    if (desired == SERVICE_DISABLED || desired == SERVICE_DEMAND_START || desired == SERVICE_AUTO_START) {
        ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, desired, SERVICE_NO_CHANGE,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

inline void ServicesMenu() {
    int pageSize = 20;
    int page = 0;
    // Cache filter
    bool showAll = true;

    while (true) {
        PrintHeader();
        PrintTitle("5. Windows Services Manager");

        auto services = ListServices();
        int total = (int)services.size();
        int pages = (total + pageSize - 1) / pageSize;

        int start = page * pageSize;
        int end   = std::min(start + pageSize, total);

        SetColor(DARK_CYAN);
        std::cout << "  Page " << (page + 1) << "/" << pages
                  << "  (Total: " << total << " services)\n\n";
        std::cout << "  " << std::left
            << std::setw(4)  << "#"
            << std::setw(30) << "Name"
            << std::setw(12) << "Status"
            << std::setw(10) << "Start"
            << "Display Name\n";
        SetColor(DARK_GRAY);
        std::cout << "  " << std::string(90, '-') << "\n";
        ResetColor();

        for (int i = start; i < end; i++) {
            auto& s = services[i];
            if (s.isSuspicious) SetColor(RED);
            else if (s.status == "Running") SetColor(GREEN);
            else SetColor(GRAY);

            std::cout << "  "
                << std::left << std::setw(4)  << (i + 1)
                << std::setw(30) << (s.name.size() > 29 ? s.name.substr(0,26)+"..." : s.name)
                << std::setw(12) << s.status
                << std::setw(10) << s.startType
                << (s.displayName.size() > 35 ? s.displayName.substr(0,32)+"..." : s.displayName)
                << "\n";
            ResetColor();
        }

        SetColor(DARK_GRAY);
        std::cout << "\n  " << std::string(90, '-') << "\n";
        ResetColor();
        SetColor(YELLOW);
        std::cout << "  [P+/P-] Page   [ST <#>] Start   [SP <#>] Stop   [DIS <#>] Disable   [EN <#>] Enable\n";
        std::cout << "  [S] Show suspicious   [0] Back\n";
        ResetColor();

        std::string cmd = InputLine("Command");
        if (cmd == "0" || cmd == "q") break;
        if (cmd == "P+" || cmd == "p+") { if (page < pages - 1) page++; continue; }
        if (cmd == "P-" || cmd == "p-") { if (page > 0) page--;         continue; }

        if (cmd == "S" || cmd == "s") {
            PrintHeader();
            PrintTitle("Suspicious Services");
            bool found = false;
            for (auto& s : services) {
                if (s.isSuspicious) {
                    SetColor(RED);
                    std::cout << "  " << s.name << " (" << s.status << ") — " << s.displayName << "\n";
                    ResetColor();
                    found = true;
                }
            }
            if (!found) PrintOK("No suspicious services detected by name heuristic.");
            Pause(); continue;
        }

        auto parseCmd = [&](const std::string& prefix) -> std::string {
            std::string p = prefix; std::transform(p.begin(), p.end(), p.begin(), ::tolower);
            std::string c = cmd;   std::transform(c.begin(), c.end(), c.begin(), ::tolower);
            if (c.substr(0, p.size()) == p && c.size() > p.size() + 1) {
                int n = -1;
                try { n = std::stoi(c.substr(p.size() + 1)); } catch (...) {}
                if (n >= 1 && n <= total) return services[n - 1].name;
            }
            return "";
        };

        std::string svcName;
        if (!(svcName = parseCmd("ST")).empty()) {
            if (ControlService_(svcName, 0, 0)) PrintOK("Started: " + svcName);
            else PrintErr("Failed to start (may need admin).");
            Pause();
        } else if (!(svcName = parseCmd("SP")).empty()) {
            if (ControlService_(svcName, SERVICE_CONTROL_STOP, 0)) PrintOK("Stopped: " + svcName);
            else PrintErr("Failed to stop.");
            Pause();
        } else if (!(svcName = parseCmd("DIS")).empty()) {
            ControlService_(svcName, SERVICE_CONTROL_STOP, SERVICE_DISABLED);
            PrintOK("Disabled: " + svcName);
            Pause();
        } else if (!(svcName = parseCmd("EN")).empty()) {
            ControlService_(svcName, 0, SERVICE_DEMAND_START);
            PrintOK("Set to Manual: " + svcName);
            Pause();
        }
    }
}
