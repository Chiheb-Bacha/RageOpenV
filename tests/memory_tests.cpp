#include <Windows.h>
#include <string>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <atomic>
#include <thread>
#include "utils/memory.h"

void logger::write(const char*, const char*, ...) {}
void logger::log(const char*, const char*, ...) {}
int replacement() { return 42; }

void require(bool ok, const char* reason) { if (!ok) throw std::runtime_error(reason); }
template<class F> void rejects(F action) {
    bool threw = false;
    try { action(); } catch (const std::exception&) { threw = true; }
    require(threw, "expected rejection, but operation succeeded");
}

int main(int argc, char** argv) {
    if (MH_Initialize() != MH_OK) return 2;
    auto image = static_cast<unsigned char*>(VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!image) return 2;
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
    dos->e_magic = IMAGE_DOS_SIGNATURE; dos->e_lfanew = 128;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(image + 128);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.NumberOfSections = 2;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
    nt->OptionalHeader.SizeOfImage = 4096;
    auto sections = IMAGE_FIRST_SECTION(nt);
    sections[0].VirtualAddress = 1024; sections[0].Misc.VirtualSize = 512;
    sections[0].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    sections[1].VirtualAddress = 2048; sections[1].Misc.VirtualSize = 512;
    sections[1].Characteristics = IMAGE_SCN_MEM_READ;
    memory::base() = reinterpret_cast<uintptr_t>(image);
    const std::string test = argc > 1 ? argv[1] : "";
    try {
        if (test == "unique") {
            image[1100] = 0xAB; image[1101] = 0xCD;
            require(memory::scan("AB ??").address == reinterpret_cast<uintptr_t>(image + 1100), "unique wildcard match");
        } else if (test == "duplicate") {
            image[1100] = image[1200] = 0xAB;
            rejects([] { memory::scan("AB"); });
        } else if (test == "missing") {
            rejects([] { memory::scan("AB CD"); });
        } else if (test == "data_only") {
            image[2100] = 0xAB;
            require(memory::scan("AB", true).address == 0, "must ignore non-executable data");
        } else if (test == "malformed") {
            rejects([] { memory::scan("GG"); });
        } else if (test == "final_offset") {
            image[1534] = 0xAB; image[1535] = 0xCD;
            require(memory::scan("AB CD").address == reinterpret_cast<uintptr_t>(image + 1534), "final legal section offset");
        } else if (test == "staged" || test == "discard" || test == "commit" || test == "conflict") {
            image[1100] = 0xAA;
            memory::begin(); memory((uintptr_t)image + 1100).put<uint8_t>(0xBB);
            require(image[1100] == 0xAA, "write happened before commit");
            if (test == "commit") { memory::commit(); require(image[1100] == 0xBB, "commit did not apply write"); }
            else if (test == "conflict") {
                image[1100] = 0xCC;
                rejects([] { memory::commit(); });
                require(image[1100] == 0xCC, "external change overwritten");
            } else { memory::discard(); require(image[1100] == 0xAA, "discard changed target"); }
        } else if (test == "null_address") {
            rejects([] { memory(0).add(1); });
            rejects([] { memory(0).rip(); });
        } else if (test == "bad_call") {
            memory::begin();
            rejects([&] { memory((uintptr_t)image + 1100).make_call((uintptr_t)image + 1200); });
            memory::discard(); require(image[1100] == 0, "invalid opcode overwritten");
        } else if (test == "raw_interior") {
            // NOP; infinite JMP at +1; RET at +3. A two-byte patch would split
            // two original instructions if the worker resumed at +1.
            const unsigned char code[] = {0x90, 0xEB, 0xFE, 0xC3};
            memcpy(image + 1100, code, sizeof(code));
            FlushInstructionCache(GetCurrentProcess(), image + 1100, sizeof(code));
            std::thread worker([&] { reinterpret_cast<void(*)()>(image + 1100)(); });
            auto handle = (HANDLE)worker.native_handle();
            bool observed = false;
            for (int tries = 0; tries < 1000; ++tries) {
                SuspendThread(handle);
                CONTEXT context{}; context.ContextFlags = CONTEXT_CONTROL;
                if (GetThreadContext(handle, &context)) observed = context.Rip == (uintptr_t)image + 1101;
                ResumeThread(handle);
                if (observed) break;
                Sleep(1);
            }
            memory::begin(); memory((uintptr_t)image + 1100).put<uint16_t>(0x90C3);
            bool rejected = false;
            try { memory::commit(); } catch (const std::exception&) { rejected = true; }
            SuspendThread(handle);
            CONTEXT context{}; context.ContextFlags = CONTEXT_CONTROL;
            GetThreadContext(handle, &context); context.Rip = (uintptr_t)image + 1103;
            SetThreadContext(handle, &context); ResumeThread(handle); worker.join();
            require(observed && rejected, "raw patch interior was not rejected");
            require(image[1100] == 0x90 && image[1101] == 0xEB, "raw patch interior changed code");
        } else if (test == "hook_commit" || test == "hook_discard" || test == "rollback" || test == "partial_activation" || test == "concurrent") {
            const unsigned char code[] = {0xB8,7,0,0,0,0xC3,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90};
            memcpy(image + 1100, code, sizeof(code));
            FlushInstructionCache(GetCurrentProcess(), image + 1100, sizeof(code));
            auto call = reinterpret_cast<int(*)()>(image + 1100); int (*original)() = nullptr;
            image[1200] = 0xAA;
            memory::begin();
            memory((uintptr_t)image + 1200).put<uint8_t>(0xBB);
            memory((uintptr_t)image + 1100).hook(replacement, &original);
            require(call() == 7, "hook activated before commit");
            if (test == "hook_commit" || test == "concurrent") {
                std::atomic<bool> running{true}, bad{false};
                std::thread worker;
                if (test == "concurrent") worker = std::thread([&] {
                    while (running.load()) { auto value = call(); if (value != 7 && value != 42) bad.store(true); }
                });
                memory::commit(); require(call() == 42, "hook not activated");
                require(original() == 7, "original trampoline not callable");
                running.store(false);
                if (worker.joinable()) worker.join();
                require(!bad.load(), "concurrent caller observed corrupt instructions");
                MH_DisableHook(image + 1100); MH_RemoveHook(image + 1100);
            } else if (test == "partial_activation") {
                MH_TestFailTransactionAfterEnable(1);
                rejects([] { memory::commit(); });
                require(call() == 7, "partially activated hook survived rollback");
                require(image[1200] == 0xAA, "partial activation left raw patch applied");
            } else if (test == "rollback") {
                MH_RemoveHook(image + 1100); // cause activation to fail after staged writes
                rejects([] { memory::commit(); });
                require(image[1200] == 0xAA, "failed activation did not roll back bytes");
                require(call() == 7, "failed activation changed original function");
            } else {
                memory::discard(); require(call() == 7, "discarded hook still active");
                require(image[1200] == 0xAA, "discarded write applied");
            }
        } else if (test == "thread_exit_churn") {
            std::atomic<bool> running{true};
            std::thread churn([&] {
                while (running.load()) {
                    auto handle = CreateThread(nullptr, 0, [](LPVOID) -> DWORD { return 0; }, nullptr, 0, nullptr);
                    if (handle) { WaitForSingleObject(handle, INFINITE); CloseHandle(handle); }
                }
            });
            MH_STATUS failure = MH_OK;
            unsigned char before = image[1200];
            int completed = 0;
            for (; completed < 1000; ++completed) {
                unsigned char after = before ^ 1;
                MH_RAW_PATCH patch{image + 1200, &before, &after, 1};
                failure = MH_ApplyPatchTransaction(&patch, 1, nullptr, 0);
                if (failure != MH_OK || image[1200] != after) break;
                before = after;
            }
            running.store(false); churn.join();
            require(completed == 1000, (std::string("thread exit churn rejected valid transaction: ") + MH_StatusToString(failure)).c_str());        } else if (test == "unwind" || test == "chained_unwind") {
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] = {2200, sizeof(RUNTIME_FUNCTION)};
            auto entry = reinterpret_cast<RUNTIME_FUNCTION*>(image + 2200);
            entry->BeginAddress = 1100; entry->EndAddress = 1300;
            entry->UnwindData = 2300; image[2300] = 1; image[2301] = 5;
            if (test == "chained_unwind") {
                image[2300] = 1 | (4 << 3);
                rejects([&] { memory((uintptr_t)image + 1220).function_start(); });
            } else require(memory((uintptr_t)image + 1220).function_start().address == (uintptr_t)image + 1100,
                    "function start must come from unwind metadata");
            rejects([&] { memory((uintptr_t)image + 1400).function_start(); });
        } else { throw std::runtime_error("unknown test"); }
        std::cout << "PASS " << test << '\n';
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << test << ": " << e.what() << '\n';
        MH_Uninitialize(); VirtualFree(image, 0, MEM_RELEASE); return 1;
    }
    MH_Uninitialize(); VirtualFree(image, 0, MEM_RELEASE); return 0;
}


