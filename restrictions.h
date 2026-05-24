#pragma once
#include "utils.h"

// ─── Each restriction: display name, registry path, value name, "locked" DWORD ──
struct Restriction {
    const char*    name;
    HKEY           root;
    const wchar_t* path;
    const wchar_t* valueName;
    DWORD          lockedVal;   // value that means "disabled by policy"
};

static const Restriction kRestrictions[] = {
    // Task Manager
    { "Task Manager disabled",
      HKEY_CURRENT_USER,
      L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
      L"DisableTaskMgr", 1 },
    // Registry Editor
    { "Registry Editor (regedit) disabled",
      HKEY_CURRENT_USER,
      L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
      L"DisableRegistryTools", 1 },
    // CMD / Command Prompt
    { "Command Prompt disabled",
      HKEY_CURRENT_USER,
      L"Software\\Policies\\Microsoft\\Windows\\System",
      L"DisableCMD", 1 },
    // Run dialog (Win+R)
    { "Run dialog disabled",
      HKEY_CURRENT_USER,
      L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
      L"NoRun", 1 },
    // Control Panel
    { "Control Panel disabled",
      HKEY_CURRENT_USER,
      L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
      L"NoControlPanel", 1 },
    // Folder Options (hide file extensions, hidden files forced by malware)
    { "Folder Options hidden (malware tactic)",
      HKEY_CURRENT_USER,
      L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
      L"NoFolderOptions", 1 },
    // Safe Mode boot blocked by some malware
    { "Safe Mode boot blocked (malware)",
      HKEY_LOCAL_MACHINE,
      L"System\\CurrentControlSet\\Control\\SafeBoot\\Minimal",
      L"AlternateShell", 0 }, // special — see unlock logic
    // Windows Update disabled
    { "Windows Update disabled",
      HKEY_LOCAL_MACHINE,
      L"Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
      L"NoAutoUpdate", 1 },
    // Msconfig blocked
    { "MSConfig disabled",
      HKEY_CURRENT_USER,
      L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
      L"DisableMsConfig", 1 },
    // Show hidden files (force enable — malware hides itself)
    { "Hidden files NOT shown (recommended: show)",
      HKEY_CURRENT_USER,
      L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
      L"Hidden", 0 }, // 0 = hidden files not visible; we want 1
};

inline bool IsLocked(const Restriction& r) {
    HKEY hKey;
    if (RegOpenKeyExW(r.root, r.path, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false; // key doesn't exist = not locked
    DWORD val = 0, size = sizeof(DWORD), type;
    LONG res = RegQueryValueExW(hKey, r.valueName, NULL, &type, (BYTE*)&val, &size);
    RegCloseKey(hKey);
    if (res != ERROR_SUCCESS) return false;
    return val == r.lockedVal;
}

inline bool Unlock(const Restriction& r) {
    // For "Hidden files" we set to 1 (show); for Safe Mode special key we just delete; rest we delete or set 0
    if (std::wstring(r.valueName) == L"Hidden")
        return RegSetDW(r.root, r.path, r.valueName, 1);
    return RegDelVal(r.root, r.path, r.valueName);
}

inline void RestrictionsMenu() {
    while (true) {
        PrintHeader();
        PrintTitle("3. Windows Restrictions Unlocker");

        SetColor(DARK_CYAN);
        std::cout << "  " << std::left << std::setw(4) << "#" << std::setw(44) << "Restriction" << "Status\n";
        SetColor(DARK_GRAY);
        std::cout << "  " << std::string(70, '-') << "\n";
        ResetColor();

        bool anyLocked = false;
        int count = (int)(sizeof(kRestrictions) / sizeof(kRestrictions[0]));
        for (int i = 0; i < count; i++) {
            auto& r = kRestrictions[i];
            bool locked = IsLocked(r);
            if (locked) anyLocked = true;

            std::cout << "  " << std::left << std::setw(4) << (i + 1)
                      << std::setw(44) << r.name;
            if (locked) { SetColor(RED);   std::cout << "  [LOCKED]\n"; }
            else        { SetColor(GREEN); std::cout << "  [OK]\n"; }
            ResetColor();
        }

        SetColor(DARK_GRAY);
        std::cout << "\n  " << std::string(70, '-') << "\n";
        ResetColor();
        SetColor(YELLOW);
        std::cout << "  [U <#>] Unlock specific   [A] Unlock ALL locked   [R] Refresh   [0] Back\n";
        ResetColor();

        std::string cmd = InputLine("Command");
        if (cmd == "0" || cmd == "q") break;
        if (cmd == "R" || cmd == "r") continue;

        if (cmd == "A" || cmd == "a") {
            int fixed = 0;
            for (int i = 0; i < count; i++) {
                if (IsLocked(kRestrictions[i])) {
                    if (Unlock(kRestrictions[i])) {
                        PrintOK(std::string("Unlocked: ") + kRestrictions[i].name);
                        fixed++;
                    } else {
                        PrintErr(std::string("Failed: ") + kRestrictions[i].name + " (try as admin)");
                    }
                }
            }
            if (fixed == 0) PrintInfo("Nothing was locked.");
            else PrintOK(std::to_string(fixed) + " restriction(s) removed.");
            Pause();
            continue;
        }

        if ((cmd[0] == 'U' || cmd[0] == 'u') && cmd.size() > 2) {
            int n = -1;
            try { n = std::stoi(cmd.substr(2)); } catch (...) {}
            if (n < 1 || n > count) { PrintErr("Invalid number."); Pause(); continue; }
            auto& r = kRestrictions[n - 1];
            if (!IsLocked(r)) { PrintInfo("Already unlocked."); }
            else if (Unlock(r)) PrintOK(std::string("Unlocked: ") + r.name);
            else PrintErr("Failed (may need admin rights).");
            Pause();
        }
    }
}
