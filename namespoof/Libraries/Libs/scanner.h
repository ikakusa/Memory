#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <ranges>
#include <optional>
#include <algorithm>
#include <Windows.h>
#include <Psapi.h>

/*
  ______
 /      \
/$$$$$$  |  _______   ______   _______   _______    ______    ______
$$ \__$$/  /       | /      \ /       \ /       \  /      \  /      \
$$      \ /$$$$$$$/  $$$$$$  |$$$$$$$  |$$$$$$$  |/$$$$$$  |/$$$$$$  |
 $$$$$$  |$$ |       /    $$ |$$ |  $$ |$$ |  $$ |$$    $$ |$$ |  $$/
/  \__$$ |$$ \_____ /$$$$$$$ |$$ |  $$ |$$ |  $$ |$$$$$$$$/ $$ |
$$    $$/ $$       |$$    $$ |$$ |  $$ |$$ |  $$ |$$       |$$ |
 $$$$$$/   $$$$$$$/  $$$$$$$/ $$/   $$/ $$/   $$/  $$$$$$$/ $$/


dev    {
	https://github.com/ikakusa
	https://github.com/nosdayoo
	https://github.com/KaeruClient
}
github : https://github.com/ikakusa/Memory ‰¼

*/

namespace scanner {

	class sig;

	#define INRANGE(x,a,b)		(x >= a && x <= b) 
	#define getBits( x )		(INRANGE(x,'0','9') ? (x - '0') : ((x&(~0x20)) - 'A' + 0xa))
	#define getByte( x )		(getBits(x[0]) << 4 | getBits(x[1]))

	typedef unsigned char byte;
	typedef std::uint64_t length;
	typedef std::vector<sig> signature;
	typedef std::string_view view;

	class sig {
	public:
		byte _byte;
		bool iswild;
		sig(byte _byte, bool iswild) : _byte(_byte), iswild(iswild){};
	};

	class process {
	private:
		static inline view current;
	public:
		static inline void set(const view&);

		[[nodiscard]] static inline length base();
		[[nodiscard]] static inline length size();
	};

	enum class find_type {
		x1 = 1,
		x4 = 4,
	};

	class access {
	public:
		template <typename ret, typename type>
		[[nodiscard]] static inline ret& at(type* _type, size_t _offset);

		[[nodiscard]] static inline signature parse_pattern(const view& pattern);
		[[nodiscard]] static inline uintptr_t find_pattern(const length start, const length end, const signature pattern, find_type type = find_type::x4);
	};


	/* scanner::process */

	void process::set(const view& in) {
		current = in;
	}
	length scanner::process::base() {
		return reinterpret_cast<length>(GetModuleHandleA(current.data()));
	}
	length scanner::process::size() { 
		static HMODULE data = (HMODULE)base();
		if (!data) return 0;

		MODULEINFO mi;
		return GetModuleInformation(GetCurrentProcess(), data, &mi, sizeof(mi)) ? mi.SizeOfImage : 0;
	}
	/* scanner::process */


	/* scanner::access */

	template <typename ret, typename type>
	ret& access::at(type* _type, size_t _offset) {
		return *reinterpret_cast<ret*>(reinterpret_cast<size_t>(_type) + _offset);
	}
	signature access::parse_pattern(const view& pattern) {
		signature sig;
		for (const auto& p : pattern | std::views::split(' ')) {
			if (p[0] == '\?') {
				sig.push_back({ 0x0, true });
			}
			else {
				byte b = getByte(p);
				sig.push_back({ b, false });
			}
		}
		return sig;
	}
	uintptr_t access::find_pattern(const length start, const length end, const signature pattern, find_type type) {
		if (start >= end || pattern.empty()) return 0;

		const auto size = pattern.size();
		const auto& front = pattern.front(), & back = pattern.back();
		const auto start_byte = (byte*)start, end_byte = (byte*)end - (size - 1);

		const auto match_side = [&front, &back, &size](byte* data) {
			if (front.iswild && back.iswild) return true;
			if (!front.iswild && !back.iswild) {
				return data[0] == front._byte && data[size - 1] == back._byte;
			}
			return (front.iswild || data[0] == front._byte) && (back.iswild || data[size - 1] == back._byte);
		};
		const auto match_all = [&pattern, &size](byte* data) {
			for (size_t i = 1; i < size - 1; i++) {
				if (data[i] != pattern[i]._byte && !pattern[i].iswild) return false;
			}
			return true;
		};

		for (auto i = start_byte; i <= end_byte; i += (int)type) {
			if (match_side(i) && match_all(i)) return start + (i - start_byte);
		}

		return 0;
	}
	/* scanner::access */

}