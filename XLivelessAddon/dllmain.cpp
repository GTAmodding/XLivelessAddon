#include <windows.h>
#include <stdint.h>
#include ".\includes\IniReader\IniReader.h"
#include ".\includes\injector\injector.hpp"
#include ".\includes\injector\calling.hpp"
#include ".\includes\injector\hooking.hpp"
#include ".\includes\injector\assembly.hpp"
#include ".\includes\injector\utility.hpp"
#include ".\includes\hooking\Hooking.Patterns.h"

bool bDelay;
char* pszPath;
char* szCustomSavePath;

// change savefile path to "%USERPROFILE%\Documents\Rockstar Games\GTA IV\savegames\"
void getSavefilePath(int __unused, char * pBuffer, char * pszSaveName)
{
    if (strlen(szCustomSavePath) == 0)
    {
        strcpy_s(pBuffer, 256, pszPath);
        strcat_s(pBuffer, 256, "savegames");
    }
    else
    {
        strcpy_s(pBuffer, 256, szCustomSavePath);
    }

    // check path and create directory if necessary
    DWORD attrs = GetFileAttributes(pBuffer);
    if (attrs == INVALID_FILE_ATTRIBUTES)
        CreateDirectory(pBuffer, NULL);
    else if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        strcpy_s(pBuffer, 256, pszSaveName);
        return;
    }

    if (pszSaveName) {
        strcat_s(pBuffer, 256, "\\");
        strcat_s(pBuffer, 256, pszSaveName);
    }
}

HANDLE CreateFileHook(_In_ LPCSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode, _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, _In_ DWORD dwCreationDisposition, _In_ DWORD dwFlagsAndAttributes, _In_opt_ HANDLE hTemplateFile)
{
    HANDLE hFile = CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    return hFile;
}

BOOL CloseHandleHook(_In_ HANDLE hObject)
{
    __try
    {
        BOOL retval = CloseHandle(hObject);

        return retval;
    }
    __except (EXCEPTION_CONTINUE_EXECUTION)
    {

    }

    return TRUE;
}

BOOL GetFileSizeExHook(HANDLE hFile, PLARGE_INTEGER lpFileSize)
{
    return GetFileSizeEx(hFile, lpFileSize);
}

BOOL ReadFileHook(HANDLE hFile, LPVOID pBuffer, DWORD nNumberOfBytesRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    return ReadFile(hFile, pBuffer, nNumberOfBytesRead, lpNumberOfBytesRead, lpOverlapped);
}

DWORD SetFilePointerHook(HANDLE hFile, LONG dtm, PLONG dtmHigh, DWORD mm)
{
    return SetFilePointer(hFile, dtm, dtmHigh, mm);
}

DWORD WINAPI Init(LPVOID)
{
    auto pattern = hook::pattern("68 88 13 00 00 FF 15");
    if (!(pattern.size() > 0) && !bDelay)
    {
        bDelay = true;
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&Init, NULL, 0, NULL);
        return 0;
    }

    if (bDelay)
    {
        while (!(pattern.size() > 0))
            pattern = hook::pattern("68 88 13 00 00 FF 15");
    }

    CIniReader iniReader("");
    szCustomSavePath = iniReader.ReadString("MAIN", "CustomSavePath", "");
    bool bRemoveRegistryPathDependencyEFLC = iniReader.ReadInteger("MAIN", "RemoveRegistryPathDependencyEFLC", 1) != 0;
    bool bSkipWebConnect = iniReader.ReadInteger("MAIN", "SkipWebConnect", 0) != 0;
    bool bSkipIntro = iniReader.ReadInteger("MAIN", "SkipIntro", 0) != 0;
    bool bDoNotPauseOnMinimize = iniReader.ReadInteger("MAIN", "DoNotPauseOnMinimize", 0) != 0;

    // Unprotect image - make .text and .rdata section writeable
    // get load address of the exe
    DWORD dwLoadOffset = (DWORD)GetModuleHandle(NULL);
    BYTE * pImageBase = reinterpret_cast<BYTE *>(dwLoadOffset);
    PIMAGE_DOS_HEADER   pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER> (dwLoadOffset);
    PIMAGE_NT_HEADERS   pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS> (pImageBase + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);

    for (int iSection = 0; iSection < pNtHeader->FileHeader.NumberOfSections; ++iSection, ++pSection) {
        char * pszSectionName = reinterpret_cast<char *>(pSection->Name);
        if (!strcmp(pszSectionName, ".text") || !strcmp(pszSectionName, ".rdata")) {
            DWORD dwPhysSize = (pSection->Misc.VirtualSize + 4095) & ~4095;
            DWORD	oldProtect;
            DWORD   newProtect = (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
            if (!VirtualProtect(reinterpret_cast <VOID *>(dwLoadOffset + pSection->VirtualAddress), dwPhysSize, newProtect, &oldProtect)) {
                ExitProcess(0);
            }
        }
    }

    static bool isEFLC = false;
    pattern = hook::pattern("68 ? ? ? ? E8 ? ? ? ? 8B F0 83 C4 ? 85 F6 0F 84 ? ? ? ? 6A 04");
    if (pattern.size() > 0)
    {
        if (strstr(*(char**)pattern.get(0).get<char*>(1), "EFLC") != NULL)
        {
            isEFLC = true;
        }
    }

    // process patches
    pattern = hook::pattern("68 88 13 00 00 FF 15");
    if (pattern.size() > 0)
        injector::WriteMemory(pattern.get(0).get<uintptr_t>(1), 1, true); // 0x401835 disable sleep

    pattern = hook::pattern("81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? 00 00 53 56 8B 35 ? ? ? ? 68");
    if (pattern.size() > 0)
        injector::WriteMemory<uint8_t>(pattern.get(0).get<uintptr_t>(0), 0xC3, true); // 0xD356D0 RETN - enable debugger in error menu (don't load WER.dll)

    pattern = hook::pattern("81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? ? ? 53 8B 9C 24 ? ? ? ? 55 8B AC ? ? ? ? ? 8B 45 00");
    if (pattern.size() > 0)
        injector::WriteMemory(pattern.get(0).get<uintptr_t>(0), 0x900008C2, true); // 0x403F10 RETN 8 - certificates check  

    pattern = hook::pattern("8B 56 1C 3B 56 20 ? ? 6A 00 6A 00");
    if (pattern.size() > 0)
    {
        injector::WriteMemory(pattern.get(0).get<uintptr_t>(0), 0x4AE9C033, true); // 0x40262D xor eax, eax - address of the RGSC object
        injector::WriteMemory(pattern.get(0).get<uintptr_t>(4), 0x90000002, true); // 0x402631 jmp 40287E (skip RGSC connect and EFC checks)	
    }

    pattern = hook::pattern("89 35 ? ? ? ? E8 ? ? ? ? 83 C4 04 84 C0");
    if (pattern.size() > 0)
        injector::WriteMemory<uint16_t>(pattern.get(0).get<uintptr_t>(0), 0xA390, true); // 0x402883 NOP; MOV [g_rgsc], eax

    pattern = hook::pattern("83 C4 04 3B 46 ? C7 06 00 00 00 00 74 ? 6A 00 6A 00");
    if (pattern.size() > 0)
        injector::MakeNOP(pattern.get(0).get<uintptr_t>(12), 0x2A, true); // 0x4028ED data integrity checks

    pattern = hook::pattern("0F 85 ? ? ? ? 8B 8C 24 ? ? ? ? 5F 5E 5B 33 CC C6");
    if (pattern.size() > 0)
        injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 6, true); // 0x40291D NOP*6- last RGSC init check


    // skip missing tests...
    pattern = hook::pattern("83 EC 24 A1 ? ? ? ? 8B 48 14 53 55 56 57");
    if (pattern.size() > 0)
        injector::WriteMemory(pattern.get(0).get<uintptr_t>(0), 0x90C3C033, true); // 0x403870 xor eax, eax; retn

    pattern = hook::pattern("83 EC 08 8B 0D ? ? ? ? 8B 51 14 8D 04 24 50 6A 00 52");
    if (pattern.size() > 0)
        injector::WriteMemory(pattern.get(0).get<uintptr_t>(0), 0x90C3C033, true); // 0x404250 xor eax, eax; retn

    pattern = hook::pattern("0F 85 ? ? ? ? 85 C0 0F 84 ? ? ? ? E8 ? ? ? ? 85 D2");
    if (pattern.size() > 0)
        injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 14, true); // 0x402B12

    pattern = hook::pattern("0F 85 ? ? ? ? 85 C0 0F 84 ? ? ? ? E8 ? ? ? ? B9");
    if (pattern.size() > 0)
        injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 14, true); // 0x402D17

    //pattern = hook::pattern("8B 35 ? ? ? ? 85 F6 74 ? E8 ? ? ? ? 83 3D ? ? ? ? 00 74 ?");
    //if (pattern.size() > 0)
    //	injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 24, true); // 0x493D4C


    // savegames
    pszPath = *hook::pattern("8A 88 ? ? ? ? 88 88 ? ? ? ? 83 C0 01 84 C9 75 ? EB ? EB ?").get(1).get<char*>(2);

    pattern = hook::pattern("75 ? 83 C1 01 83 C0 01 83 F9 04");
    if (pattern.size() > 0)
        injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 2, true); // 0x5B06E5 NOP; NOP - save file CRC32 check

    pattern = hook::pattern("55 8B EC 83 E4 F8 83 EC 4C 56");
    if (pattern.size() > 0)
        injector::MakeJMP(pattern.get(0).get<uintptr_t>(0), getSavefilePath, true); // 0x5B0110 replace getSavefilePath


    // fix messed sequences
    pattern = hook::pattern("A1 ? ? ? ? 85 C0 8B 0D ? ? ? ? 75");
    if (pattern.size() > 0)
    {
        injector::WriteMemory(pattern.get(0).get<uintptr_t>(0), 0x90C301B0, true); // 0xBAC160  mov al, 1; retn
        injector::WriteMemory(pattern.get(1).get<uintptr_t>(0), 0x90C301B0, true); // 0xBAC190  mov al, 1; retn
    }

    pattern = hook::pattern("33 C0 83 3D ? ? ? ? 01 0F 94 C0 C3");
    if (pattern.size() > 0)
    {
        injector::WriteMemory(pattern.get(3).get<uintptr_t>(0), 0x90C301B0, true); // 0xBAC180  mov al, 1; retn
        injector::WriteMemory(pattern.get(4).get<uintptr_t>(0), 0x90C301B0, true); // 0xBAC1C0  mov al, 1; retn
    }


    // DLC
    // token activation
    pattern = hook::pattern("8B 54 24 04 52 A3");
    if (pattern.size() > 0)
        injector::WriteMemory<uint16_t>(pattern.get(0).get<uintptr_t>(0), 0xC9EB, true); // 0x813196

    pattern = hook::pattern("83 F8 01 75 30 A3");
    if (pattern.size() > 0)
    {
        injector::WriteMemory<uint8_t>(pattern.get(0).get<uintptr_t>(0), 0xB8, true); // 0x813161
        injector::WriteMemory(pattern.get(0).get<uintptr_t>(1), 1, true);
    }

    // skip first-time play ask
    pattern = hook::pattern("C7 05 ? ? ? ? 03 00 00 00 33 C0 5E 59 C3 C7");
    if (pattern.size() > 0)
        injector::WriteMemory<uint16_t>(pattern.get(0).get<uintptr_t>(0), 0x0DEB, true); // 0x831049

    // DFA
    pattern = hook::pattern("55 8B EC 6A 00 E8");
    if (pattern.size() > 0)
        injector::MakeJMP(pattern.get(0).get<uintptr_t>(0), CreateFileHook, true); // 0xD2F994

    pattern = hook::pattern("6A 00 E8 ? ? ? ? 83 F8 01 59 75 17");
    if (pattern.size() > 0)
    {
        injector::MakeJMP(pattern.get(0).get<uintptr_t>(0), CloseHandleHook, true); // 0xD2FB2C
        injector::MakeJMP(pattern.get(1).get<uintptr_t>(0), SetFilePointerHook, true); // 0xD2FB53
    }

    pattern = hook::pattern("56 8B 74 24 0C 8D 46");
    if (pattern.size() > 0)
        injector::MakeJMP(pattern.get(0).get<uintptr_t>(0), GetFileSizeExHook, true); // 0xD2FBA2

    pattern = hook::pattern("55 8B EC 51 51 53 56 8B C5");
    if (pattern.size() > 0)
        injector::MakeJMP(pattern.get(0).get<uintptr_t>(0), ReadFileHook, true); // 0xD2F9F9

    pattern = hook::pattern("A1 ? ? ? ? B9 A7 FA DC 5C F7 E1 8B 0D ? ? ? ? 33 F6");
    if (pattern.size() > 0)
    {
        injector::MakeJMP(pattern.get(0).get<uintptr_t>(0), hook::pattern("80 BC 24 ? 02 00 00 00 6A").get(0).get<uintptr_t>(0), true); // 0x5AAF57 to 0x5AB077
        injector::MakeJMP(pattern.get(1).get<uintptr_t>(0), hook::pattern("6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 57").get(0).get<uintptr_t>(0), true); // 0x5AB11B to 0x5AB23B
    }


    if (isEFLC && bRemoveRegistryPathDependencyEFLC)
    {
        struct RegPatch
        {
            void operator()(injector::reg_pack& regs)
            {
                HMODULE hModule = GetModuleHandle(NULL);
                if (hModule != NULL)
                {
                    GetModuleFileName(hModule, (char*)regs.esi, 260);
                    auto ptr = strrchr((char*)regs.esi, '\\');
                    *(ptr + 1) = '\0';
                }
            }
        };

        struct RegPatch2
        {
            void operator()(injector::reg_pack& regs)
            {
                regs.ecx = *(uintptr_t*)(regs.esp + 0x4);
                HMODULE hModule = GetModuleHandle(NULL);
                if (hModule != NULL)
                {
                    GetModuleFileName(hModule, (char*)regs.esi, 260);
                    auto ptr = strrchr((char*)regs.esi, '\\');
                    *(ptr + 1) = '\0';
                }
            }
        };

        //eflc registry dependency
        pattern = hook::pattern("74 ? 8D ? ? ? ? 68 19 00 02 00 6A 00 68 ? ? ? ? 68 01 00 00 80 FF D6 85 C0"); //0x7FE12C
        if (pattern.size() > 0)
            injector::WriteMemory<uint8_t>(pattern.get(0).get<uintptr_t>(0), 0xEB, true);

        if (pattern.size() > 3)
            injector::WriteMemory<uint8_t>(pattern.get(2).get<uintptr_t>(0), 0xEB, true); //0x8B329C

        pattern = hook::pattern("0F 85 ? ? ? ? 53 88 86 03 01"); //0x7FE1B8
        if (pattern.size() > 0)
            injector::MakeInline<RegPatch>(pattern.get(0).get<uintptr_t>(0), pattern.get(0).get<uintptr_t>(6));

        pattern = hook::pattern("75 ? 8B 4C 24 04 51 88 86 03 01 00 00"); //0x8B3315
        if (pattern.size() > 0)
            injector::MakeInline<RegPatch2>(pattern.get(0).get<uintptr_t>(0), pattern.get(0).get<uintptr_t>(6));
    }

    if (bSkipWebConnect)
    {
        pattern = hook::pattern("75 07 A0"); // 0x7AF1B7 isInternetConnectionPresent
        injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 2, true);

        pattern = hook::pattern("81 EC 94 09 00 00"); // 0x87FC60 health check
        injector::WriteMemory<uint8_t>(pattern.get(0).get<uintptr_t>(0), 0xC3, true);
    }

    if (bSkipIntro)
    {
        pattern = hook::pattern("74 ? 80 3D ? ? ? ? 00 74 ? E8 ? ? ? ? 0F"); //0x473439
        injector::WriteMemory<uint8_t>(pattern.get(0).get<uintptr_t>(0), 0xEB, true);
    }

    if (bDoNotPauseOnMinimize)
    {
        pattern = hook::pattern("75 ? 8B 0D ? ? ? ? 51 FF 15 ? ? ? ? 85 C0 75 ? 8B 15"); //0x402D5A
        injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 2, true);
    }

    return 0;
}


BOOL APIENTRY DllMain(HMODULE /*hModule*/, DWORD reason, LPVOID /*lpReserved*/)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        Init(NULL);
    }
    return TRUE;
}
