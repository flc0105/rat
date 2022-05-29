#include <iostream>
#include <windows.h>

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReversed)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		char DllPath[MAX_PATH];
		GetModuleFileName((HINSTANCE)&__ImageBase, DllPath, _countof(DllPath));
		std::string Path = DllPath;
		WinExec((Path.substr(0, Path.find_last_of('\\', Path.length())) + "\\client.exe").c_str(), SW_SHOWNORMAL);
		ExitProcess(0);
	}
	return TRUE;
}