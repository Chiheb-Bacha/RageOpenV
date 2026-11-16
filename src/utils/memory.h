#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <functional>
#include <string>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include "vendor/minhook/include/MinHook.h"
#include "log.h"

class memory {
    struct Patch { uintptr_t at; std::vector<unsigned char> before, after; };
    inline static bool preparing = false;
    inline static std::vector<Patch> patches;
    inline static std::vector<void*> hooks;
    inline static size_t arenaUsed = 0;
    inline static bool residualActive = false;
    static constexpr size_t arenaSize = 4096;
    static void readable(uintptr_t at, size_t len) {
        if (!at || !len || at > UINTPTR_MAX - len) throw std::runtime_error("invalid memory range");
        auto end = at + len;
        while (at < end) {
            MEMORY_BASIC_INFORMATION info{};
            if (!VirtualQuery((void*)at, &info, sizeof(info)) || info.State != MEM_COMMIT ||
                (info.Protect & (PAGE_NOACCESS | PAGE_GUARD))) throw std::runtime_error("unreadable memory range");
            at = std::min(end, (uintptr_t)info.BaseAddress + info.RegionSize);
        }
    }
    static void write(uintptr_t at, const void* bytes, size_t len) {
        if (!preparing) throw std::runtime_error("write outside patch transaction");
        readable(at, len);
        auto p = (const unsigned char*)bytes;
        patches.push_back({at, {(unsigned char*)at, (unsigned char*)at + len}, {p, p + len}});
    }
    static std::vector<int> parse(const char* signature) {
        std::istringstream input(signature ? signature : ""); std::string token; std::vector<int> bytes;
        auto digit = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        while (input >> token) {
            if (token == "?" || token == "??") bytes.push_back(-1);
            else {
                if (token.size() != 2 || digit(token[0]) < 0 || digit(token[1]) < 0) throw std::runtime_error("malformed signature");
                bytes.push_back(digit(token[0]) * 16 + digit(token[1]));
            }
        }
        if (bytes.empty() || std::all_of(bytes.begin(), bytes.end(), [](int b) { return b < 0; })) throw std::runtime_error("empty or unconstrained signature");
        return bytes;
    }
public:
    uintptr_t address;
    memory(const memory&) = default;
    memory& operator=(const memory&) = default;
    memory(uintptr_t offset, bool useBase = false) : address(useBase ? base() + offset : offset) {}
    static uintptr_t& base() { static uintptr_t value = 0; return value; }
    static memory& virtual_mem() { static memory value(0); return value; }
    static bool residual_active() noexcept { return residualActive; }
    static void begin() {
        if (preparing || residualActive || !hooks.empty()) throw std::runtime_error("nested or uncleared patch transaction");
        patches.clear(); hooks.clear(); arenaUsed = 0; preparing = true;
    }
    static bool discard() noexcept {
        if (residualActive) { patches.clear(); preparing = false; return false; }
        for (size_t i = hooks.size(); i > 0; --i) {
            const auto status = MH_RemoveHook(hooks[i - 1]);
            if (status == MH_OK || status == MH_ERROR_NOT_CREATED) hooks.erase(hooks.begin() + i - 1);
        }
        if (!hooks.empty()) residualActive = true;
        patches.clear(); preparing = false;
        if (!residualActive) arenaUsed = 0;
        return !residualActive;
    }
    static void commit() {
        if (!preparing) throw std::runtime_error("no patch transaction");
        try {
            std::vector<MH_RAW_PATCH> batch;
            batch.reserve(patches.size());
            for (const auto& p : patches) {
                readable(p.at, p.before.size());
                batch.push_back({(void*)p.at, p.before.data(), p.after.data(), p.before.size()});
            }
            // MinHook owns its lock before suspending threads. All buffers are
            // allocated above; raw writes and hook activation share one barrier.
            const auto result = MH_ApplyPatchTransaction(batch.data(), (UINT)batch.size(), hooks.data(), (UINT)hooks.size());
            if (result != MH_OK) {
                residualActive = result == MH_ERROR_TRANSACTION_ROLLBACK;
                throw std::runtime_error(std::string(residualActive ? "incomplete transaction rollback; restart the game: " : "resource transaction rejected and rolled back: ") + MH_StatusToString(result));
            }
            patches.clear(); hooks.clear(); preparing = false;
        } catch (...) {
            discard(); throw;
        }
    }
    struct InitFuncs {
        std::function<void()> fn;
        static std::vector<InitFuncs>& funcs() { static std::vector<InitFuncs> list; return list; }
        static void run() {
            begin();
            try { for (auto& cb : funcs()) cb.fn(); commit(); }
            catch (...) { discard(); throw; }
        }
        InitFuncs(const std::function<void()>& action) : fn(action) { funcs().push_back(*this); }
    };
    static void init() {
        base() = (uintptr_t)GetModuleHandleW(nullptr);
        SYSTEM_INFO info{}; GetSystemInfo(&info);
        const auto step = (uintptr_t)info.dwAllocationGranularity;
        auto anchor = base() & ~(step - 1);
        for (uintptr_t distance = step; distance < 0x70000000; distance += step) {
            for (auto candidate : {anchor + distance, anchor > distance ? anchor - distance : uintptr_t(0)}) {
                if (!candidate) continue;
                auto block = VirtualAlloc((void*)candidate, arenaSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (block) { virtual_mem() = memory((uintptr_t)block); break; }
            }
            if (virtual_mem().address) break;
        }
        if (!virtual_mem().address) throw std::runtime_error("cannot allocate nearby trampolines");
        if (MH_Initialize() != MH_OK) throw std::runtime_error("MinHook initialization failed");
    }
    static memory get_virtual_mem(size_t size) {
        if (!preparing || !virtual_mem().address) throw std::runtime_error("trampoline arena unavailable");
        arenaUsed = (arenaUsed + 15) & ~size_t(15);
        if (size > arenaSize - arenaUsed) throw std::runtime_error("trampoline arena exhausted");
        auto out = memory(virtual_mem().address + arenaUsed); arenaUsed += size; return out;
    }
    template<class T> T as() const { if (!address) throw std::runtime_error("unresolved address"); return (T)address; }
    template<class T> memory add(T offset) const {
        if (!address) throw std::runtime_error("offset from unresolved address");
        return memory(address + offset);
    }
    memory rip() const {
        readable(address, 4); int32_t offset{}; memcpy(&offset, (void*)address, 4);
        auto target = address + 4 + offset; readable(target, 1); return memory(target);
    }
    memory function_start() const {
        readable(base(), sizeof(IMAGE_DOS_HEADER));
        auto dos = (const IMAGE_DOS_HEADER*)base();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < sizeof(IMAGE_DOS_HEADER)) throw std::runtime_error("invalid DOS header");
        readable(base() + dos->e_lfanew, sizeof(IMAGE_NT_HEADERS));
        auto nt = (const IMAGE_NT_HEADERS*)(base() + dos->e_lfanew);
        auto directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (address < base() || address - base() >= nt->OptionalHeader.SizeOfImage || !directory.Size ||
            directory.VirtualAddress >= nt->OptionalHeader.SizeOfImage ||
            directory.Size > nt->OptionalHeader.SizeOfImage - directory.VirtualAddress || directory.Size % sizeof(RUNTIME_FUNCTION))
            throw std::runtime_error("invalid unwind metadata");
        readable(base() + directory.VirtualAddress, directory.Size);
        auto entries = (const RUNTIME_FUNCTION*)(base() + directory.VirtualAddress);
        const auto rva = address - base();
        for (size_t i = 0; i < directory.Size / sizeof(RUNTIME_FUNCTION); ++i) {
            if (entries[i].BeginAddress <= rva && rva < entries[i].EndAddress) {
                if (entries[i].EndAddress > nt->OptionalHeader.SizeOfImage) throw std::runtime_error("invalid function bounds");
                const auto unwind = entries[i].UnwindData;
                if (unwind >= nt->OptionalHeader.SizeOfImage || unwind > nt->OptionalHeader.SizeOfImage - 4)
                    throw std::runtime_error("invalid unwind info");
                readable(base() + unwind, 4);
                const auto info = (const unsigned char*)(base() + unwind);
                if ((info[0] & 7) != 1 || (info[0] >> 3) & 4)
                    throw std::runtime_error("unsupported or chained unwind entry");
                if (!info[1] || info[1] >= entries[i].EndAddress - entries[i].BeginAddress)
                    throw std::runtime_error("unverified function prologue");
                return memory(base() + entries[i].BeginAddress);
            }
        }
        throw std::runtime_error("no unwind entry for function");
    }
    void nop(size_t len) { std::vector<unsigned char> data(len, 0x90); write(address, data.data(), len); }
    void ret() { put<uint8_t>(0xC3); }
    void make_jmp(uintptr_t target) {
        unsigned char data[12] = {0x48, 0xB8}; memcpy(data + 2, &target, 8); data[10] = 0xFF; data[11] = 0xE0;
        write(address, data, 12);
    }
    void make_jmp_ret(void* target) { make_jmp_ret((uintptr_t)target); }
    void make_jmp_ret(uintptr_t target) {
        unsigned char data[12] = {0x48, 0xB8}; memcpy(data + 2, &target, 8); data[10] = 0x50; data[11] = 0xC3;
        write(address, data, 12);
    }
    void make_call(uintptr_t target) {
        readable(address, 5);
        if (*(unsigned char*)address != 0xE8) throw std::runtime_error("expected CALL rel32 opcode");
        int64_t delta = (int64_t)target - (int64_t)address - 5;
        if (delta < INT32_MIN || delta > INT32_MAX) throw std::runtime_error("rel32 target out of range");
        int32_t relative = (int32_t)delta; unsigned char data[5] = {0xE8}; memcpy(data + 1, &relative, 4);
        write(address, data, 5);
    }
    void set_call(void* target, bool useRet = false) {
        auto trampoline = get_virtual_mem(12);
        if (useRet) trampoline.make_jmp_ret(target); else trampoline.make_jmp((uintptr_t)target);
        make_call(trampoline.address);
    }
    template<class T> void put(const T& value) { write(address, &value, sizeof(T)); }
    template<class R = void*, class... Args> R call(Args... args) { readable(address, 1); return ((R(*)(Args...))address)(args...); }
    template<class T> void hook(T* target, T** original = nullptr) {
        if (!preparing) throw std::runtime_error("hook outside transaction");
        readable(address, 1);
        if (MH_CreateHook((void*)address, (void*)target, (void**)original) != MH_OK) throw std::runtime_error("cannot create resource hook");
        hooks.push_back((void*)address);
    }
    template<class Ret, class... Args> class func {
        using Fn = Ret(__fastcall*)(Args...); Fn fn = nullptr; std::string signature;
    public:
        func(const char* pattern) : signature(pattern) { new InitFuncs([this] { run(); }); }
        void run() { fn = memory::scan(signature.c_str()).template as<Fn>(); }
        Ret operator()(Args... args) { if (!fn) throw std::runtime_error("unresolved function"); return fn(args...); }
    };
    static bool HookApi(const wchar_t* module, const char* name, PVOID target, PVOID* original) {
        void* resolved = nullptr;
        if (MH_CreateHookApiEx(module, name, target, original, &resolved) != MH_OK) return false;
        if (MH_EnableHook(resolved) != MH_OK) { MH_RemoveHook(resolved); return false; }
        return true;
    }
    static memory scan(const char* signature, bool optional = false) {
        auto pattern = parse(signature);
        readable(base(), sizeof(IMAGE_DOS_HEADER));
        auto dos = (const IMAGE_DOS_HEADER*)base();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < sizeof(IMAGE_DOS_HEADER)) throw std::runtime_error("invalid DOS header");
        readable(base() + dos->e_lfanew, sizeof(IMAGE_NT_HEADERS));
        auto nt = (const IMAGE_NT_HEADERS*)(base() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || !nt->OptionalHeader.SizeOfImage) throw std::runtime_error("invalid PE header");
        auto sections = IMAGE_FIRST_SECTION(nt);
        readable((uintptr_t)sections, sizeof(IMAGE_SECTION_HEADER) * nt->FileHeader.NumberOfSections);
        uintptr_t match = 0;
        for (unsigned index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
            auto& section = sections[index];
            if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            size_t rva = section.VirtualAddress, length = section.Misc.VirtualSize;
            if (rva >= nt->OptionalHeader.SizeOfImage || length > nt->OptionalHeader.SizeOfImage - rva) throw std::runtime_error("invalid executable section");
            if (length < pattern.size()) continue;
            readable(base() + rva, length); auto data = (const unsigned char*)(base() + rva);
            for (size_t i = 0; i <= length - pattern.size(); ++i) {
                size_t j = 0;
                while (j < pattern.size() && (pattern[j] < 0 || data[i + j] == pattern[j])) ++j;
                if (j != pattern.size()) continue;
                if (match) throw std::runtime_error(std::string("ambiguous signature: ") + signature);
                match = base() + rva + i;
            }
        }
        if (!match && !optional) throw std::runtime_error(std::string("missing signature: ") + signature);
        logger::write("info", "signature %s => RVA %llx", signature, match ? match - base() : 0ull);
        return memory(match);
    }
};

