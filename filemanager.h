#pragma once
#include "utils.h"
#include <vector>
#include <filesystem>
#include <algorithm>
namespace fs = std::filesystem;

// ─── Suspicious file patterns ────────────────────────────────────────────────
static const std::vector<std::wstring> kSuspiciousExts = {
    L".exe", L".bat", L".cmd", L".vbs", L".js", L".ps1", L".scr", L".pif", L".com"
};
static const std::vector<std::wstring> kMalwarePaths = {
    // %TEMP%
    L"\\AppData\\Local\\Temp",
    L"\\AppData\\Roaming",
    L"\\Users\\Public",
};

struct FileEntry {
    fs::path   path;
    uintmax_t  sizeBytes;
    bool       isDir;
    bool       suspicious;
};

inline bool IsSuspiciousFile(const fs::path& p) {
    std::wstring ext = p.extension().wstring();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    for (auto& e : kSuspiciousExts)
        if (ext == e) return true;
    return false;
}

inline std::string FormatSize(uintmax_t bytes) {
    if (bytes < 1024) return std::to_string(bytes) + " B";
    if (bytes < 1024*1024) return std::to_string(bytes/1024) + " KB";
    return std::to_string(bytes/1024/1024) + " MB";
}

inline std::vector<FileEntry> ListDir(const fs::path& dir) {
    std::vector<FileEntry> list;
    std::error_code ec;
    for (auto& e : fs::directory_iterator(dir, fs::directory_options::skip_permission_denied, ec)) {
        FileEntry fe;
        fe.path  = e.path();
        fe.isDir = e.is_directory(ec);
        fe.sizeBytes = fe.isDir ? 0 : e.file_size(ec);
        fe.suspicious = !fe.isDir && IsSuspiciousFile(e.path());
        list.push_back(fe);
    }
    std::sort(list.begin(), list.end(), [](auto& a, auto& b){
        if (a.isDir != b.isDir) return a.isDir > b.isDir;
        return a.path.filename().wstring() < b.path.filename().wstring();
    });
    return list;
}

// ─── Scan common malware drop locations ──────────────────────────────────────
inline void ScanMalwareLocations() {
    PrintHeader();
    PrintTitle("Scan Malware Drop Locations");

    std::vector<std::wstring> paths;
    // TEMP
    wchar_t tmp[MAX_PATH]{};
    GetTempPathW(MAX_PATH, tmp);
    paths.push_back(tmp);
    // Startup folders
    paths.push_back(L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");

    // Per-user AppData
    wchar_t appdata[MAX_PATH]{};
    if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appdata) == S_OK)
        paths.push_back(appdata);

    int totalSuspicious = 0;
    for (auto& p : paths) {
        PrintInfo("Scanning: " + w2s(p));
        std::error_code ec;
        for (auto& e : fs::recursive_directory_iterator(p,
            fs::directory_options::skip_permission_denied, ec)) {
            if (e.is_regular_file(ec) && IsSuspiciousFile(e.path())) {
                SetColor(YELLOW);
                std::cout << "  [?] " << w2s(e.path().wstring()) << "\n";
                ResetColor();
                totalSuspicious++;
            }
        }
    }
    if (totalSuspicious == 0) PrintOK("No suspicious executables found in common drop locations.");
    else PrintWarn("Found " + std::to_string(totalSuspicious) + " suspicious file(s). Review manually.");
    Pause();
}

inline void FileManagerMenu() {
    fs::path currentDir = "C:\\";
    int pageSize = 20;
    int page = 0;

    while (true) {
        PrintHeader();
        PrintTitle("6. File Manager");

        SetColor(DARK_CYAN);
        std::cout << "  Path: " << currentDir.string() << "\n\n";
        ResetColor();

        std::vector<FileEntry> entries;
        std::error_code ec;
        if (!fs::exists(currentDir, ec)) {
            PrintErr("Path does not exist: " + currentDir.string());
        } else {
            entries = ListDir(currentDir);
        }

        int total = (int)entries.size();
        int pages = total > 0 ? (total + pageSize - 1) / pageSize : 1;
        if (page >= pages) page = pages - 1;
        int start = page * pageSize;
        int end   = std::min(start + pageSize, total);

        // Parent dir
        SetColor(DARK_CYAN);
        std::cout << "  [..] Parent directory\n";
        ResetColor();

        SetColor(DARK_CYAN);
        std::cout << "  " << std::left
            << std::setw(4)  << "#"
            << std::setw(45) << "Name"
            << std::setw(12) << "Size"
            << "\n";
        SetColor(DARK_GRAY);
        std::cout << "  " << std::string(65, '-') << "\n";
        ResetColor();

        for (int i = start; i < end; i++) {
            auto& fe = entries[i];
            if (fe.isDir) SetColor(CYAN);
            else if (fe.suspicious) SetColor(YELLOW);
            else SetColor(GRAY);

            std::string name = fe.path.filename().string();
            std::cout << "  "
                << std::left << std::setw(4)  << (i + 1)
                << std::setw(45) << (name.size() > 44 ? name.substr(0,41)+"..." : name)
                << (fe.isDir ? "<DIR>" : FormatSize(fe.sizeBytes))
                << "\n";
            ResetColor();
        }

        SetColor(DARK_GRAY);
        std::cout << "\n  Page " << (page+1) << "/" << pages << "  |  " << total << " items\n";
        std::cout << "  " << std::string(65, '-') << "\n";
        ResetColor();
        SetColor(YELLOW);
        std::cout << "  [#]  Open dir / select file\n";
        std::cout << "  [CD <path>] Go to path  [P+/P-] Page  [..] Up\n";
        std::cout << "  [DEL <#>] Delete file   [SCAN] Scan malware locations   [0] Back\n";
        ResetColor();

        std::string cmd = InputLine("Command");
        if (cmd == "0" || cmd == "q") break;
        if (cmd == "P+" || cmd == "p+") { if (page < pages-1) page++; continue; }
        if (cmd == "P-" || cmd == "p-") { if (page > 0) page--;       continue; }
        if (cmd == "..")  { if (currentDir.has_parent_path()) { currentDir = currentDir.parent_path(); page = 0; } continue; }
        if (cmd == "SCAN" || cmd == "scan") { ScanMalwareLocations(); continue; }

        if (cmd.size() > 3 && (cmd.substr(0,3) == "CD " || cmd.substr(0,3) == "cd ")) {
            fs::path newp = s2w(cmd.substr(3));
            if (fs::exists(newp) && fs::is_directory(newp)) { currentDir = newp; page = 0; }
            else PrintErr("Directory not found: " + cmd.substr(3));
            Pause(); continue;
        }

        if (cmd.size() > 4 && (cmd.substr(0,4) == "DEL " || cmd.substr(0,4) == "del ")) {
            int n = -1;
            try { n = std::stoi(cmd.substr(4)); } catch (...) {}
            if (n < 1 || n > total) { PrintErr("Invalid number."); Pause(); continue; }
            auto& fe = entries[n - 1];
            if (fe.isDir) { PrintErr("Use DEL only for files. To remove dir, type its number first."); Pause(); continue; }
            SetColor(RED);
            std::cout << "  Delete: " << fe.path.string() << " ? (y/n): ";
            ResetColor();
            std::string confirm; std::getline(std::cin, confirm);
            if (confirm == "y" || confirm == "Y") {
                std::error_code ec2;
                if (fs::remove(fe.path, ec2)) PrintOK("Deleted: " + fe.path.string());
                else PrintErr("Failed: " + ec2.message());
            } else PrintInfo("Cancelled.");
            Pause(); continue;
        }

        // Try to navigate by number
        int n = -1;
        try { n = std::stoi(cmd); } catch (...) {}
        if (n >= 1 && n <= total) {
            auto& fe = entries[n - 1];
            if (fe.isDir) { currentDir = fe.path; page = 0; }
            else {
                SetColor(GRAY);
                std::cout << "\n  File: " << fe.path.string() << "\n";
                std::cout << "  Size: " << FormatSize(fe.sizeBytes) << "\n";
                SetColor(YELLOW);
                std::cout << "  [D] Delete   [Any] Cancel: ";
                ResetColor();
                std::string ch; std::getline(std::cin, ch);
                if (ch == "D" || ch == "d") {
                    std::error_code ec2;
                    if (fs::remove(fe.path, ec2)) PrintOK("Deleted.");
                    else PrintErr("Failed: " + ec2.message());
                    Pause();
                }
            }
        }
    }
}
