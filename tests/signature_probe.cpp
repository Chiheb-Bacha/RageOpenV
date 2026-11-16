#include <Windows.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <sstream>
#include "utils/memory.h"
void logger::write(const char*, const char*, ...) {}
void logger::log(const char*, const char*, ...) {}

// Maps file bytes as data only: no imports, entrypoint, hooks, or game execution.
int main(int argc, char** argv) {
    if (argc != 3) { std::cerr << "usage: signature_probe game.exe manifest.tsv\n"; return 2; }
    try {
        std::ifstream input(argv[1], std::ios::binary);
        std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(input)), {});
        if (bytes.size() < sizeof(IMAGE_DOS_HEADER)) throw std::runtime_error("EXE not readable");
        auto dos = (const IMAGE_DOS_HEADER*)bytes.data();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
            (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > bytes.size()) throw std::runtime_error("bad DOS header");
        auto nt = (const IMAGE_NT_HEADERS*)(bytes.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            throw std::runtime_error("bad PE64 header");
        const size_t size = nt->OptionalHeader.SizeOfImage;
        auto mapped = (unsigned char*)VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!mapped) throw std::runtime_error("cannot allocate image");
        auto sec = IMAGE_FIRST_SECTION(nt);
        if (nt->OptionalHeader.SizeOfHeaders > bytes.size() || nt->OptionalHeader.SizeOfHeaders > size)
            throw std::runtime_error("bad headers size");
        memcpy(mapped, bytes.data(), nt->OptionalHeader.SizeOfHeaders);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (sec[i].PointerToRawData > bytes.size() || sec[i].SizeOfRawData > bytes.size() - sec[i].PointerToRawData ||
                sec[i].VirtualAddress > size || sec[i].SizeOfRawData > size - sec[i].VirtualAddress)
                throw std::runtime_error("bad section");
            memcpy(mapped + sec[i].VirtualAddress, bytes.data() + sec[i].PointerToRawData, sec[i].SizeOfRawData);
        }
        memory::base() = (uintptr_t)mapped;
        std::ifstream manifest(argv[2]);
        if (!manifest) throw std::runtime_error("manifest missing");
        std::string line; int failed = 0, count = 0;
        while (std::getline(manifest, line)) {
            if (line.empty()) continue;
            std::istringstream row(line); std::string label, pattern, offset;
            std::getline(row, label, '\t'); std::getline(row, pattern, '\t'); std::getline(row, offset);
            ++count;
            try {
                auto match = memory::scan(pattern.c_str());
                std::cout << "PASS " << label << " RVA=0x" << std::hex << match.address - memory::base() << std::dec;
                if (!offset.empty()) {
                    const auto value = std::stoll(offset, nullptr, 0);
                    if (value < 0) {
                        auto start = match.function_start();
                        std::cout << " unwind_delta=" << (int64_t)start.address - (int64_t)match.address;
                        if (start.address != match.add(value).address) throw std::runtime_error("upstream offset and unwind disagree");
                    } else {
                        auto call = match.add(value);
                        if (*(unsigned char*)call.address != 0xE8) throw std::runtime_error("expected callsite not CALL rel32");
                        call.add(1).rip();
                    }
                }
                std::cout << '\n';
            } catch (const std::exception& e) { ++failed; std::cout << " FAIL: " << e.what() << '\n'; }
        }
        VirtualFree(mapped, 0, MEM_RELEASE);
        std::cout << "Checked=" << count << " Failed=" << failed << '\n';
        return failed || !count ? 1 : 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 2; }
}
