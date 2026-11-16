#include "main.h"
#include "status.h"
#include <atomic>

// 0: waiting, 1: discovery, 2: active, 3: incompatible/failed.
static std::atomic<int> initState{0};
static void (*origGetSystemTimeAsFileTime)(LPFILETIME);

// Don't hide the console. Optional: a missing pattern never cancels initialization.
static memory::InitFuncs ConsolePatch([] {
    if (IsEnhanced()) {
        auto site = memory::scan("ff 15 ? ? ? ? 48 85 c0 74 ? 48 89 c1 31 d2", true);
        if (site.address) site.add(16).nop(6);
    } else {
        // Kept for backwards compatibility, as it is unknown when this pattern stopped working.
        auto site = memory::scan("FF 15 ? ? ? ? E8 ? ? ? ? 65 48 8B 0C 25 ? ? ? ? 8B 05 ? ? ? ? 48 8B 04 C1 BA ? ? ? ? 83 24 02 00 E8", true);
        if (!site.address) {
            site = memory::scan("ff 15 ? ? ? ? 65 48 8b 0c 25 ? ? ? ? 8b 05 ? ? ? ? ba", true);
            if (site.address) site.nop(6);
        }
    }
});

static memory::InitFuncs CachePatch([] {
    if (IsEnhanced()) {
        // Mandatory on Enhanced; absence must cancel the complete transaction.
        auto site = memory::scan("e8 ? ? ? ? 48 8d 0d ? ? ? ? 48 8d 15 ? ? ? ? 48 8d 35");
        site.add(1).rip().put<uint16_t>(0x90c3);
    }
});

void HookGetSystemTimeAsFileTime(LPFILETIME time) noexcept {
    int expected = 0;
    if (initState.compare_exchange_strong(expected, 1)) {
        WriteLoaderStatus("checking", "Discovering and validating required hooks");
        try {
            memory::InitFuncs::run();
            initState.store(2);
            logger::write("info", " RageOpenV Inited!");
            WriteLoaderStatus("active", "All required patches and hooks activated; in-game validation still required");
        } catch (const std::exception& e) {
            initState.store(3);
            WriteLoaderStatus(memory::residual_active() ? "failed-restart-required" : "disabled", e.what());
        } catch (...) {
            initState.store(3);
            WriteLoaderStatus(memory::residual_active() ? "failed-restart-required" : "disabled", "Unknown initialization failure");
        }
    }
    origGetSystemTimeAsFileTime(time);
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        try {
            config::load();
            logger::init();
            memory::init();
            if (config::get_config<bool>("console")) {
                AllocConsole();
                FILE* unused = nullptr;
                freopen_s(&unused, "CONIN$", "r", stdin);
                freopen_s(&unused, "CONOUT$", "w", stdout);
                freopen_s(&unused, "CONOUT$", "w", stderr);
            }
            WriteLoaderStatus("waiting", "Waiting for game initialization");
            if (!memory::HookApi(L"kernel32.dll", "GetSystemTimeAsFileTime", (PVOID)HookGetSystemTimeAsFileTime,
                (PVOID*)&origGetSystemTimeAsFileTime)) {
                initState.store(3);
                WriteLoaderStatus("disabled", "Cannot install initialization hook");
            }
        } catch (const std::exception& e) {
            initState.store(3); WriteLoaderStatus("disabled", e.what());
        } catch (...) {
            initState.store(3); WriteLoaderStatus("disabled", "Bootstrap failure");
        }
    }
    return TRUE;
}
