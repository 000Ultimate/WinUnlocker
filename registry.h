#pragma once
#include "utils.h"
#include <vector>
#include <filesystem>

struct RegIssue {
    std::string  description;
    HKEY         root;
    std::wstring path;
    std::wstring valueName;
    bool         deleteKey;   // true = delete entire key; false = delete value
    bool         fixed;
};

// ─── Check if file/path from registry value actually exists ──────────────────
inline bool FileExistsFromRegValue(const std::wstring& raw) {
    // Strip quotes, extract executable path (stop at first space if no quotes)
    std::wstring path = raw;
    if (!path.empty() && path[0] == L'"') {
        size_t end = path.find(L'"', 1);
        path = path.substr(1, end == std::wstring::npos ? std::wstring::npos : end - 1);
    } else {
        size_t sp = path.find(L' ');
        if (sp != std::wstring::npos) path = path.substr(0, sp);
    }
    // Expand environment strings
    wchar_t expanded[MAX_PATH * 2]{};
    ExpandEnvironmentStringsW(path.c_str(), expanded, MAX_PATH * 2);
    return GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES;
}

// ─── Scan a Run key for broken entries ───────────────────────────────────────
inline void ScanRunKey(HKEY root, const wchar_t* path, const char* label,
                       std::vector<RegIssue>& issues)
{
    HKEY hKey;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;

    DWORD idx = 0;
    wchar_t name[512]; BYTE data[2048]; DWORD nameLen, dataLen, type;
    while (true) {
        nameLen = _countof(name); dataLen = sizeof(data);
        if (RegEnumValueW(hKey, idx++, name, &nameLen, NULL, &type, data, &dataLen) != ERROR_SUCCESS) break;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

        std::wstring val = reinterpret_cast<wchar_t*>(data);
        if (!FileExistsFromRegValue(val)) {
            RegIssue issue;
            issue.description = std::string("Broken autorun (") + label + "): " + w2s(name)
                              + " -> " + w2s(val);
            issue.root      = root;
            issue.path      = path;
            issue.valueName = name;
            issue.deleteKey = false;
            issue.fixed     = false;
            issues.push_back(issue);
        }
    }
    RegCloseKey(hKey);
}

// ─── Scan Uninstall keys for broken entries ───────────────────────────────────
inline void ScanUninstallKey(HKEY root, const wchar_t* basePath,
                             std::vector<RegIssue>& issues)
{
    HKEY hBase;
    if (RegOpenKeyExW(root, basePath, 0, KEY_READ, &hBase) != ERROR_SUCCESS) return;

    DWORD idx = 0;
    wchar_t subName[512];
    DWORD subLen;
    while (true) {
        subLen = _countof(subName);
        if (RegEnumKeyExW(hBase, idx++, subName, &subLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;

        std::wstring subPath = std::wstring(basePath) + L"\\" + subName;
        HKEY hSub;
        if (RegOpenKeyExW(root, subPath.c_str(), 0, KEY_READ, &hSub) != ERROR_SUCCESS) continue;

        wchar_t installLoc[MAX_PATH * 2]{};
        DWORD size = sizeof(installLoc), type;
        bool broken = false;
        if (RegQueryValueExW(hSub, L"InstallLocation", NULL, &type,
            (BYTE*)installLoc, &size) == ERROR_SUCCESS && wcslen(installLoc) > 0) {
            if (GetFileAttributesW(installLoc) == INVALID_FILE_ATTRIBUTES)
                broken = true;
        }
        RegCloseKey(hSub);

        if (broken) {
            RegIssue issue;
            issue.description = "Broken uninstall entry: " + w2s(subName);
            issue.root      = root;
            issue.path      = subPath;
            issue.valueName = L"";
            issue.deleteKey = true;
            issue.fixed     = false;
            issues.push_back(issue);
        }
    }
    RegCloseKey(hBase);
}

inline std::vector<RegIssue> ScanRegistry() {
    std::vector<RegIssue> issues;

    // Autorun keys
    ScanRunKey(HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",      "HKCU Run",     issues);
    ScanRunKey(HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",  "HKCU RunOnce", issues);
    ScanRunKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",      "HKLM Run",     issues);
    ScanRunKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",  "HKLM RunOnce", issues);

    // Uninstall entries
    ScanUninstallKey(HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", issues);
    ScanUninstallKey(HKEY_LOCAL_MACHINE,
        L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", issues);

    return issues;
}

inline bool FixIssue(RegIssue& issue) {
    bool ok;
    if (issue.deleteKey) {
        // RegDeleteKeyExW recursively would need more code; simple delete for leaf keys
        ok = (RegDeleteKeyW(issue.root, issue.path.c_str()) == ERROR_SUCCESS);
    } else {
        ok = RegDelVal(issue.root, issue.path, issue.valueName);
    }
    if (ok) issue.fixed = true;
    return ok;
}

inline void RegistryMenu() {
    while (true) {
        PrintHeader();
        PrintTitle("4. Registry Cleaner");

        PrintInfo("Scanning registry for broken entries...");
        auto issues = ScanRegistry();

        if (issues.empty()) {
            PrintOK("Registry looks clean — no broken entries found.");
            Pause();
            break;
        }

        SetColor(DARK_CYAN);
        std::cout << "  " << std::left << std::setw(4) << "#" << "Issue\n";
        SetColor(DARK_GRAY);
        std::cout << "  " << std::string(80, '-') << "\n";
        ResetColor();

        for (size_t i = 0; i < issues.size(); i++) {
            SetColor(YELLOW);
            std::cout << "  " << std::left << std::setw(4) << (i + 1);
            ResetColor();
            std::cout << issues[i].description << "\n";
        }

        SetColor(DARK_GRAY);
        std::cout << "\n  Found " << issues.size() << " issue(s).\n";
        std::cout << "  " << std::string(80, '-') << "\n";
        ResetColor();
        SetColor(YELLOW);
        std::cout << "  [F <#>] Fix specific   [A] Fix ALL   [R] Rescan   [0] Back\n";
        ResetColor();

        std::string cmd = InputLine("Command");
        if (cmd == "0" || cmd == "q") break;
        if (cmd == "R" || cmd == "r") continue;

        if (cmd == "A" || cmd == "a") {
            int fixed = 0;
            for (auto& iss : issues) {
                if (FixIssue(iss)) { PrintOK("Fixed: " + iss.description); fixed++; }
                else PrintErr("Failed: " + iss.description);
            }
            PrintInfo("Fixed " + std::to_string(fixed) + " / " + std::to_string(issues.size()) + " issues.");
            Pause();
            continue;
        }

        if ((cmd[0] == 'F' || cmd[0] == 'f') && cmd.size() > 2) {
            int n = -1;
            try { n = std::stoi(cmd.substr(2)); } catch (...) {}
            if (n < 1 || n > (int)issues.size()) { PrintErr("Invalid number."); Pause(); continue; }
            if (FixIssue(issues[n - 1])) PrintOK("Fixed: " + issues[n - 1].description);
            else PrintErr("Failed (may need admin rights).");
            Pause();
        }
    }
}
