#include <iostream>
#include <windows.h>

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

using namespace std;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		char DllPath[MAX_PATH];
		GetModuleFileName((HINSTANCE)&__ImageBase, DllPath, _countof(DllPath));
		string path = DllPath;
		path = path.substr(0, path.find_last_of('.', path.length())) + ".exe";
		WinExec(path.c_str(), SW_SHOWNORMAL);
		ExitProcess(0);
	}
}