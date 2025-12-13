// Shared HookRow definition used across UI and controller
#pragma once
#include <string>
#include <tuple>
#include <vector>
#ifndef _WINDEF_
#include <Windows.h>
#endif

// canonical HookRow in global namespace so existing code can refer to `HookRow`
struct HookRow {
    int id;
    unsigned long long address;
    std::wstring module;
    std::wstring expFunc; // dllname!exportfunctionname
	unsigned long long ori_asm_code_addr;
    unsigned long ori_asm_code_len;
	unsigned long long trampoline_pit;
};

namespace HookRowUtils {

    using PersistTuple = std::tuple<DWORD, DWORD, DWORD, int, DWORD, unsigned long long, unsigned long long, unsigned long long, std::wstring, std::wstring>;

    inline PersistTuple ToPersistTuple(const HookRow& r, DWORD pid, DWORD hi, DWORD lo) {
        return std::make_tuple(pid, hi, lo, r.id, r.ori_asm_code_len, r.ori_asm_code_addr, r.trampoline_pit, r.address, r.module, r.expFunc);
    }

    inline HookRow FromPersistTuple(const PersistTuple& t) {
        HookRow r;
        r.id = std::get<3>(t);
        r.ori_asm_code_len = std::get<4>(t);
        r.ori_asm_code_addr = std::get<5>(t);
        r.trampoline_pit = std::get<6>(t);
        r.address = std::get<7>(t);
        r.module = std::get<8>(t);
        r.expFunc = std::get<9>(t);
        return r;
    }

    inline std::vector<PersistTuple> ToPersistVector(const std::vector<HookRow*>& rows, DWORD pid, DWORD hi, DWORD lo) {
        std::vector<PersistTuple> out; out.reserve(rows.size());
        for (auto r : rows) {
            if (!r) continue;
            out.push_back(ToPersistTuple(*r, pid, hi, lo));
        }
        return out;
    }

}
