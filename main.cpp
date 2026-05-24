#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <shlobj.h>
#include <shellapi.h>
#pragma comment(lib, "shell32.lib")

#include "utils.h"
#include "tasks.h"
#include "autorun.h"
#include "restrictions.h"
#include "registry.h"
#include "services.h"
#include "filemanager.h"

// ─── Request UAC elevation if not already elevated ───────────────────────────
static void RequestElevation() {
    if (IsElevated()) return;

    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(NULL, path, MAX_PATH);

    // Re-launch self as admin
    SHELLEXECUTEINFOW sei{};
    sei.cbSize       = sizeof(sei);
    sei.lpVerb       = L"runas";
    sei.lpFile       = path;
    sei.nShow        = SW_SHOWNORMAL;
    if (ShellExecuteExW(&sei)) {
        ExitProcess(0); // old instance exits
    }
    // If user cancelled UAC — continue without elevation, warn later
}

// ─── System info banner ───────────────────────────────────────────────────────
static void PrintSysInfo() {
    // Windows version
    OSVERSIONINFOEXW ovi{};
    ovi.dwOSVersionInfoSize = sizeof(ovi);
#pragma warning(suppress: 4996)
    GetVersionExW(reinterpret_cast<OSVERSIONINFOW*>(&ovi));

    char compName[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD sz = sizeof(compName);
    GetComputerNameA(compName, &sz);

    char userName[256]{};
    DWORD usz = sizeof(userName);
    GetUserNameA(userName, &usz);

    SetColor(DARK_GRAY);
    std::cout << "  System : Windows " << ovi.dwMajorVersion << "." << ovi.dwMinorVersion
              << " Build " << ovi.dwBuildNumber << "\n";
    std::cout << "  Host   : " << compName << "   User: " << userName << "\n";
    if (IsElevated()) { SetColor(GREEN);  std::cout << "  Rights : Administrator\n"; }
    else              { SetColor(YELLOW); std::cout << "  Rights : Standard User  (some features need admin!)\n"; }
    ResetColor();
    std::cout << "\n";
}

// ─── Main menu ────────────────────────────────────────────────────────────────
static void MainMenu() {
    while (true) {
        PrintHeader();
        PrintSysInfo();

        SetColor(DARK_CYAN);
        std::cout << "  ┌─────────────────────────────────────────────┐\n";
        std::cout << "  │              MAIN MENU                      │\n";
        std::cout << "  ├─────────────────────────────────────────────┤\n";
        ResetColor();

        const char* items[] = {
            "1", "Task Manager        (view / kill processes)",
            "2", "Autorun Manager     (startup entries)",
            "3", "Restrictions        (unlock Task Mgr, regedit, CMD...)",
            "4", "Registry Cleaner    (broken entries, orphans)",
            "5", "Services Manager    (Windows services)",
            "6", "File Manager        (browse / delete malware files)",
            "0", "Exit",
        };

        for (int i = 0; i < 14; i += 2) {
            SetColor(DARK_CYAN); std::cout << "  │  ";
            SetColor(YELLOW);    std::cout << items[i] << ". ";
            SetColor(GRAY);      std::cout << std::left << std::setw(42) << items[i+1];
            SetColor(DARK_CYAN); std::cout << "│\n";
            ResetColor();
        }

        SetColor(DARK_CYAN);
        std::cout << "  └─────────────────────────────────────────────┘\n\n";
        ResetColor();

        if (!IsElevated()) {
            PrintWarn("Running without admin rights — some features may not work.");
            SetColor(YELLOW);
            std::cout << "  Type 'sudo' to relaunch as Administrator.\n\n";
            ResetColor();
        }

        std::string choice = InputLine("Choose option");

        if (choice == "sudo" || choice == "SUDO") {
            RequestElevation();
            continue;
        }

        if      (choice == "1") TaskManagerMenu();
        else if (choice == "2") AutorunMenu();
        else if (choice == "3") RestrictionsMenu();
        else if (choice == "4") RegistryMenu();
        else if (choice == "5") ServicesMenu();
        else if (choice == "6") FileManagerMenu();
        else if (choice == "0" || choice == "q" || choice == "exit") {
            SetColor(DARK_CYAN);
            std::cout << "\n  Goodbye!\n\n";
            ResetColor();
            break;
        } else {
            PrintErr("Unknown option: " + choice);
            Sleep(800);
        }
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────
int main() {
    // UTF-8 console output (best-effort)
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // Set console title
    SetConsoleTitleW(L"WinUnlocker - Windows Repair Toolkit");

    // Try to enable ANSI / VT processing for better box-drawing
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    // Ask for elevation on startup
    RequestElevation();

    MainMenu();
    return 0;
}
