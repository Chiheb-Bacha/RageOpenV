#pragma once
#include <fstream>
#include <filesystem>
#include <Windows.h>

// Written even when verbose upstream logging is disabled.
inline void WriteLoaderStatus(const char* state, const char* reason) noexcept {
    try {
        wchar_t path[32768]{};
        auto len = GetModuleFileNameW(nullptr, path, 32768);
        if (!len || len == 32768) return;
        std::ofstream out(std::filesystem::path(path).parent_path() / L"RageOpenV.status.txt", std::ios::trunc);
        out << "RageOpenV\nstate=" << state << "\nedition="
            << (IsEnhanced() ? "Enhanced" : "Legacy") << "\nreason=" << reason << '\n';
    } catch (...) {}
}
