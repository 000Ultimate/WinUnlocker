#pragma once
#include "utils.h"
#include <vector>

struct AutorunEntry {
    std::string location; // e.g. "HKCU\\Run"
    std::string name;
    std::string value;
    HKEY        root;
    std::wstring regPath;
    std::wstring regName;
};

static const struct { HKEY root; const wchar_t* path; const char* label; } kAutorunKeys[] = {
    { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",                       "HKCU\\Run"        },
    { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",                   "HKCU\\RunOnce"    },
    { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",                       "HKLM\\Run"        },
    { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",                   "HKLM\\RunOnce"    },
    { HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",          "HKLM\\Run(x86)"   },
    { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",               "HKLM\\Winlogon"   },
};

inline std::vector<AutorunEntry> ListAutorun() {
    std::vector<AutorunEntry> list;
    for (auto& k : kAutorunKeys) {
        HKEY hKey;
        if (RegOpenKeyExW(k.root, k.path, 0, KEY_READ, &hKey) != ERROR_SUCCESS) continue;

        DWORD idx = 0;
        wchar_t valName[512];
        BYTE    valData[2048];
        DWORD   nameLen, dataLen, type;

        while (true) {
            nameLen = _countof(valName);
            dataLen = sizeof(valData);
            LONG res = RegEnumValueW(hKey, idx++, valName, &nameLen, NULL, &type, valData, &dataLen);
            if (res == ERROR_NO_MORE_ITEMS) break;
            if (res != ERROR_SUCCESS) continue;
            if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

            AutorunEntry e;
            e.location = k.label;
            e.name     = w2s(valName);
            e.value    = w2s(reinterpret_cast<wchar_t*>(valData));
            e.root     = k.root;
            e.regPath  = k.path;
            e.regName  = valName;
            list.push_back(e);
        }
        RegCloseKey(hKey);
    }
    return list;
}

inline void AutorunMenu() {
    while (true) {
        PrintHeader();
        PrintTitle("2. Autorun Manager");

        auto entries = ListAutorun();

        if (entries.empty()) {
            PrintInfo("No autorun entries found.");
        } else {
            SetColor(DARK_CYAN);
            std::cout << "  " << std::left
                << std::setw(4)  << "#"
                << std::setw(18) << "Location"
                << std::setw(30) << "Name"
                << "Value\n";
            SetColor(DARK_GRAY);
            std::cout << "  " << std::string(90, '-') << "\n";
            ResetColor();

            for (size_t i = 0; i < entries.size(); i++) {
                auto& e = entries[i];
                // Highlight suspicious-looking entries
                bool sus = false;
                std::string vlow = e.value;
                std::transform(vlow.begin(), vlow.end(), vlow.begin(), ::tolower);
                if (vlow.find("temp") != std::string::npos ||
                    vlow.find("appdata\\roaming") != std::string::npos ||
                    vlow.find("%tmp%") != std::string::npos)
                    sus = true;

                if (sus) SetColor(YELLOW); else SetColor(GRAY);
                std::cout << "  "
                    << std::left << std::setw(4)  << (i + 1)
                    << std::setw(18) << e.location
                    << std::setw(30) << (e.name.size() > 29 ? e.name.substr(0,26)+"..." : e.name)
                    << (e.value.size() > 55 ? e.value.substr(0,52)+"..." : e.value)
                    << "\n";
                ResetColor();
            }
        }

        SetColor(DARK_GRAY);
        std::cout << "\n  " << std::string(90, '-') << "\n";
        ResetColor();
        SetColor(YELLOW);
        std::cout << "  [D <#>] Delete entry by number   [A] Add entry   [R] Refresh   [0] Back\n";
        ResetColor();

        std::string cmd = InputLine("Command");
        if (cmd == "0" || cmd == "q") break;
        if (cmd == "R" || cmd == "r") continue;

        if ((cmd[0] == 'D' || cmd[0] == 'd') && cmd.size() > 2) {
            int n = -1;
            try { n = std::stoi(cmd.substr(2)); } catch (...) {}
            if (n < 1 || n > (int)entries.size()) {
                PrintErr("Invalid number.");
            } else {
                auto& e = entries[n - 1];
                if (RegDelVal(e.root, e.regPath, e.regName))
                    PrintOK("Deleted autorun entry: " + e.name);
                else
                    PrintErr("Failed to delete (may need elevation).");
            }
            Pause();
            continue;
        }

        if (cmd == "A" || cmd == "a") {
            std::string name  = InputLine("Entry name (e.g. MyApp)");
            std::string value = InputLine("Full path to executable");
            if (name.empty() || value.empty()) { PrintErr("Name and path cannot be empty."); Pause(); continue; }
            if (RegSetStr(HKEY_CURRENT_USER,
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                s2w(name), s2w(value)))
                PrintOK("Added autorun entry: " + name);
            else
                PrintErr("Failed to add entry.");
            Pause();
        }
    }
}
