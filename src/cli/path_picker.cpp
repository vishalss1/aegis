#include "aegis/cli/path_picker.hpp"
#include <windows.h>
#include <conio.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

static std::vector<std::string> get_directory_files(const std::string& prefix) {
    std::vector<std::string> matches;
    std::string search_pattern = prefix.empty() ? "*.*" : prefix + "*";
    
    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA(search_pattern.c_str(), &find_data);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::string name = find_data.cFileName;
            if (name != "." && name != "..") {
                if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    name += "/";
                }
                matches.push_back(name);
            }
        } while (FindNextFileA(hFind, &find_data));
        FindClose(hFind);
    }
    return matches;
}

std::string run_path_picker() {
    std::cout << "\n--- Path Picker (Tab to complete/list, Enter to select, Esc to cancel) ---\n";
    std::cout << "Select file/dir: ";
    std::fflush(stdout);

    std::string buffer;
    while (true) {
        int ch = _getch();
        if (ch == 27) { // ESC
            std::cout << "\n[Cancelled]\n";
            return "";
        } else if (ch == 13 || ch == 10) { // Enter
            std::cout << "\n";
            return buffer;
        } else if (ch == 8) { // Backspace
            if (!buffer.empty()) {
                buffer.pop_back();
                std::cout << "\b \b";
                std::fflush(stdout);
            }
        } else if (ch == 9) { // Tab
            std::vector<std::string> matches = get_directory_files(buffer);
            if (matches.empty()) {
                std::cout << " [no match]";
            } else if (matches.size() == 1) {
                // Erase current buffer from screen
                for (size_t i = 0; i < buffer.size(); ++i) std::cout << "\b \b";
                buffer = matches[0];
                std::cout << buffer;
            } else {
                std::cout << "\n";
                for (const auto& m : matches) {
                    std::cout << "  " << m << "\n";
                }
                std::cout << "Select file/dir: " << buffer;
            }
            std::fflush(stdout);
        } else if (ch >= 32 && ch <= 126) { // Printable chars
            buffer.push_back(static_cast<char>(ch));
            std::cout << static_cast<char>(ch);
            std::fflush(stdout);
        }
    }
}
