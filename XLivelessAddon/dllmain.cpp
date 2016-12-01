#include <windows.h>
#include <stdint.h>
#include ".\includes\IniReader.h"
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

	pattern = hook::pattern("A1 ? ? ? ? 85 C0 8B 0D ? ? ? ? 75");
	if (pattern.size() > 0)
	{
		injector::WriteMemory(pattern.get(0).get<uintptr_t>(0), 0x90C301B0, true); // 0xBAC160  mov al, 1; retn
		injector::WriteMemory(pattern.get(1).get<uintptr_t>(0), 0x90C301B0, true); // 0xBAC160  mov al, 1; retn
	}

	pattern = hook::pattern("33 C0 83 3D ? ? ? ? 01 0F 94 C0 C3");
	if (pattern.size() > 0)
	{
		injector::WriteMemory(pattern.get(3).get<uintptr_t>(0), 0x90C301B0, true); // 0xBAC180  mov al, 1; retn
		injector::WriteMemory(pattern.get(4).get<uintptr_t>(0), 0x90C301B0, true); // 0xBAC1C0  mov al, 1; retn
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
