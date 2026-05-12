#pragma once

#include <iostream>
#include <string>
#include <cctype>
#include <vector>

#include <Windows.h>

namespace injection {
	bool inject_dll_via_manual_map(DWORD pid, const std::wstring& dll_path);
	bool inject_dll_via_loadlibrary(DWORD pid, const std::wstring& dll_path);
	bool inject_via_loader_exe(DWORD pid, const std::wstring& loader_path = L"");
	bool launch_suspended_inject_loadlibrary(
		const std::wstring& executable_path,
		const std::vector<std::wstring>& arguments,
		const std::wstring& dll_path,
		DWORD post_inject_delay_ms,
		DWORD* out_pid = nullptr);
	bool launch_suspended_inject_loader(
		const std::wstring& executable_path,
		const std::vector<std::wstring>& arguments,
		const std::wstring& loader_path,
		DWORD post_inject_delay_ms,
		DWORD* out_pid = nullptr,
		bool resume_after_inject = true,
		HANDLE* out_primary_thread = nullptr);
};
