#include "MemUtils.h"

void MemoryUtils::init() {
	MH_Initialize();
    scanner::process::set("Minecraft.windows.exe");
	isInitialized = true;
}

void MemoryUtils::restore() {
	MH_DisableHook(MH_ALL_HOOKS);
	MH_RemoveHook(MH_ALL_HOOKS);
	MH_Uninitialize();
}

uintptr_t MemoryUtils::findSig(std::string_view signature) {
    const auto parsed = scanner::access::parse_pattern(signature);
    auto base = scanner::process::base();
    auto length = scanner::process::size();
    auto end = base + length;

    auto result = scanner::access::find_pattern(base, end, parsed);
    writelog("%x", result);
    return result;
} 

std::optional<uintptr_t> MemoryUtils::SigScanSafe(std::string_view signature) {
    const auto parsed = hat::parse_signature(signature);

    const auto begin = reinterpret_cast<std::byte*>(getBase());
    const auto end = begin + GetMinecraftSize();
    const auto result = hat::find_pattern(begin, end, parsed.value());

    if (!result.has_result()) return std::nullopt;
    return reinterpret_cast<uintptr_t>(result.get());
}