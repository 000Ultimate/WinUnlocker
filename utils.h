#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

// ====== Console Colors ======
enum Color {
    BLACK = 0, DARK_BLUE, DARK_GREEN, DARK_CYAN,
    DARK_RED, DARK_MAGENTA, DARK_YELLOW, GRAY,
    DARK_GRAY, BLUE, GREEN, CYAN, RED, MAGENTA, YELLOW, WHITE
};

inline void SetColor(Color fg, Color bg = BLACK) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), (WORD)((bg << 4) | fg));
}
inline void ResetColor() { SetColor(GRAY); }

// ====== Print helpers ======
inline void PrintTitle(const std::string& title) {
    SetColor(CYAN);
    std::cout << "\n";
    std::cout << "  ╔══════════════════════════════════════════════════╗\n";
    std::cout << "  ║  " << std::left << std::setw(48) << title << "║\n";
    std::cout << "  ╚══════════════════════════════════════════════════╝\n\n";
    ResetColor();
}

inline void PrintHeader() {
    system("cls");
    SetColor(CYAN);
    std::cout << R"(
  ██╗    ██╗██╗███╗   ██╗██╗   ██╗███╗   ██╗██╗      ██████╗  ██████╗██╗  ██╗███████╗██████╗
  ██║    ██║██║████╗  ██║██║   ██║████╗  ██║██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
  ██║ █╗ ██║██║██╔██╗ ██║██║   ██║██╔██╗ ██║██║     ██║   ██║██║     █████╔╝ █████╗  ██████╔╝
  ██║███╗██║██║██║╚██╗██║██║   ██║██║╚██╗██║██║     ██║   ██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
  ╚███╔███╔╝██║██║ ╚████║╚██████╔╝██║ ╚████║███████╗╚██████╔╝╚██████╗██║  ██╗███████╗██║  ██║
   ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
)";
    SetColor(DARK_CYAN);
    std::cout << "                  Windows Repair & Malware Removal Toolkit  v1.0\n";
    SetColor(DARK_GRAY);
    std::cout << "  ─────────────────────────────────────────────────────────────────────────────\n\n";
    ResetColor();
}

inline void PrintOK(const std::string& msg) {
    SetColor(GREEN); std::cout << "  [+] "; ResetColor();
    std::cout << msg << "\n";
}
inline void PrintErr(const std::string& msg) {
    SetColor(RED); std::cout << "  [!] "; ResetColor();
    std::cout << msg << "\n";
}
inline void PrintInfo(const std::string& msg) {
    SetColor(YELLOW); std::cout << "  [*] "; ResetColor();
    std::cout << msg << "\n";
}
inline void PrintWarn(const std::string& msg) {
    SetColor(DARK_YELLOW); std::cout << "  [~] "; ResetColor();
    std::cout << msg << "\n";
}

inline void Pause() {
    SetColor(DARK_GRAY);
    std::cout << "\n  Press Enter to continue...";
    ResetColor();
    std::cin.ignore(10000, '\n');
    std::cin.get();
}

inline std::string InputLine(const std::string& prompt) {
    SetColor(YELLOW);
    std::cout << "  > " << prompt << ": ";
    ResetColor();
    std::string s;
    std::getline(std::cin, s);
    return s;
}

inline int InputInt(const std::string& prompt) {
    std::string s = InputLine(prompt);
    try { return std::stoi(s); } catch (...) { return -1; }
}

// ====== Privilege check ======
inline bool IsElevated() {
    BOOL elevated = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION te{};
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(token, TokenElevation, &te, sizeof(te), &size))
            elevated = te.TokenIsElevated;
        CloseHandle(token);
    }
    return elevated != FALSE;
}

// ====== Registry helpers ======
inline bool RegSetStr(HKEY root, const std::wstring& path, const std::wstring& name, const std::wstring& value) {
    HKEY hKey;
    if (RegCreateKeyExW(root, path.c_str(), 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return false;
    bool ok = RegSetValueExW(hKey, name.c_str(), 0, REG_SZ,
        (BYTE*)value.c_str(), (DWORD)((value.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
    RegCloseKey(hKey);
    return ok;
}

inline bool RegSetDW(HKEY root, const std::wstring& path, const std::wstring& name, DWORD value) {
    HKEY hKey;
    if (RegCreateKeyExW(root, path.c_str(), 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return false;
    bool ok = RegSetValueExW(hKey, name.c_str(), 0, REG_DWORD,
        (BYTE*)&value, sizeof(DWORD)) == ERROR_SUCCESS;
    RegCloseKey(hKey);
    return ok;
}

inline bool RegDelVal(HKEY root, const std::wstring& path, const std::wstring& name) {
    HKEY hKey;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return false;
    bool ok = RegDeleteValueW(hKey, name.c_str()) == ERROR_SUCCESS;
    RegCloseKey(hKey);
    return ok;
}

inline std::wstring s2w(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, NULL, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, &w[0], n);
    return w;
}
inline std::string w2s(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, NULL, 0, NULL, NULL);
    std::string s(n, 0);
    WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, &s[0], n, NULL, NULL);
    return s;
}
