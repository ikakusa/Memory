#pragma once
#include "Hooks.h"

//Hooks
#include "ConnectionRequest/ConnectionRequest.h"
//
class Hook;
class HookManager {
private:
	static inline std::vector<Hook*> hooks;
	template <typename T>
		static void add() {
		static_assert(std::is_base_of<Hook, T>::value, "It isn't Hook!");
		hookList.push_back(new T);
	};
public:
	static void initHooks();
	static void DeleteHooks() {
		hooks.clear();
	}
};