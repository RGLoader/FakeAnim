// FakeAnim.cpp : Defines the entry point for the application.

#include "stdafx.h"

using namespace std;

HANDLE ModuleHandle = NULL;

BOOL MountStuff() {
	 InfoPrint("Creating mounts...\n");
	 CreateSymbolicLink("Hdd:", "\\Device\\Harddisk0\\Partition1", TRUE);
	 InfoPrint("Done!\n");

	 return TRUE;
}

BOOL ExpansionStuff() {
	/*
	0xC8007000 // address alignment fail
	0xC8007001 // size alignment fail
	0xC8007002 // magic/rsa sanity fail
	0xC8007003 // flags/size sanity fail
	0xC8007004 // inner header fail
	0xC8007005 // ...
	*/

	InfoPrint("Checking if the HVPP expansion is installed...\n");
	if (HvPeekWORD(0) != 0x5E4E) {
		// install signed and encrypted HVPP expansion
		InfoPrint("Installing HVPP expansion...\n");
		DWORD ret = InstallExpansion();
		if (ret != ERROR_SUCCESS) {
			InfoPrint("InstallExpansion: %04X\n", ret);
			return FALSE;
		}
		InfoPrint("Done!\n");
	} else
		InfoPrint("Expansion is already installed, skipping...\n");

	return TRUE;
}

BOOL PatchStuff() {
	InfoPrint("Applying HV patches...\n");
	
	PVOID pSecData;
	ULONG pSecSize;
	if (!XGetModuleSection(ModuleHandle, "patches", &pSecData, &pSecSize)) {
		InfoPrint("Error getting \"patches\" section!\n");
		return FALSE;
	}

	if (ApplyHVPatches((PBYTE)pSecData, pSecSize) == FALSE) {
		InfoPrint("Error applying patches!\n");
		return FALSE;
	}
	InfoPrint("Done!\n");

	return TRUE;
}

BOOL CPUStuff(BOOL writeToFile) {
	InfoPrint("CPU key: ");
	BYTE CPUKeyHV[0x10];
	HvPeekBytes(0x20, CPUKeyHV, 0x10);
	HexPrint(CPUKeyHV, 0x10);
	DbgPrint("\n");

	if (!writeToFile)
		return TRUE;

	InfoPrint("Writing CPU key to file...\n");
	if (!WriteFile(CPU_KEY_FILE, CPUKeyHV, 0x10)) {
		// InfoPrint("Error writing CPU key to file!\n");
		return FALSE;
	}
	InfoPrint("Done!\n");

	return TRUE;
}

BOOL FixCache(DWORD dwMb) {
	InfoPrint("Allocating %lu MB to fix PTE cache...\n", dwMb);
	DWORD dwSize = dwMb * 1024 * 1024;
	PBYTE pbTest = (PBYTE)XPhysicalAlloc(dwSize, MAXULONG_PTR, 0, PAGE_READWRITE);
	XeCryptRandom(pbTest, dwSize);
	XPhysicalFree(pbTest);
	InfoPrint("Done!\n");

	return TRUE;
}

BOOL PatchShadowbootPath() {
	PSTRING dwHd0StrPtr;
	// DWORD* dwExpTryToShadowBootPtr;

	const char Hd0BufferOld[] = "\\Device\\Harddisk0\\Partition1\\xboxromtw2d.bin";
	// needs to be equal or shorter than Hd0BufferOld
	const char Hd0BufferNew[] = "\\Device\\Harddisk0\\Partition1\\shadowboot.bin";

	DWORD Hd0BuffLookup[] = {
		0x80040514  // correct for my test kit
	};

	for (DWORD i = 0; i < (sizeof(Hd0BuffLookup) / sizeof(Hd0BuffLookup[0])); i++) {
		PSTRING hd0Str = (PSTRING)Hd0BuffLookup[i];

		// check if already patched
		if (memcmp(hd0Str->Buffer, Hd0BufferNew, hd0Str->Length) == 0) {
			dwHd0StrPtr = (PSTRING)Hd0BuffLookup[i];
			InfoPrint("Hd0 buffer already patched, skipping...\n");
			break;
		}

		// check for buffer
		if (memcmp(hd0Str->Buffer, Hd0BufferOld, hd0Str->Length) == 0) {
			dwHd0StrPtr = (PSTRING)Hd0BuffLookup[i];
			InfoPrint("Patching hd0 buffer...\n");
			ZeroMemory(hd0Str->Buffer, hd0Str->MaximumLength);
			hd0Str->Length = strlen(Hd0BufferNew);
			hd0Str->MaximumLength = strlen(Hd0BufferNew) + 1;
			memcpy(hd0Str->Buffer, Hd0BufferNew, strlen(Hd0BufferNew));  // we want it at the original location
			InfoPrint("Shadowboot Path: \"%s\" @ 0x%X\n", hd0Str->Buffer, hd0Str->Buffer);
			break;
		}
	}

	return TRUE;
}

BOOL Initialize() {  // HANDLE hModule) {
	// check power reason
	BYTE reason[0x10];
	ZeroMemory(reason, 0x10);
	HalGetPowerUpCause(reason);
	if (reason[1] == SMC_PWR_REAS_12_EJECT) {
		InfoPrint("Booted with eject button, halting execution...\n");
		return FALSE;
	}

	// create mounts as system
	MountStuff();

	// check if the expansion is already installed
	if (ExpansionStuff() == FALSE) {
		InfoPrint("Error installing expansion!\n");
		return FALSE;
	}

	// memory protection patches
	if (PatchStuff() == FALSE) {
		InfoPrint("Error installing patches!\n");
		return FALSE;
	}

	// refresh PTE tables
	if (FixCache(4) == FALSE) {
		InfoPrint("Error fixing PTE tables!\n");
		return FALSE;
	}

	// CPU key
	if (CPUStuff(FALSE) == FALSE) {
		InfoPrint("Error writing CPU key to file!\n");
		return FALSE;
	}

	// patch hd0 buffer
	if (PatchShadowbootPath() == FALSE) {
		InfoPrint("Error patching shadowboot path!\n");
	}

	// shadowboot will happen automatically right after this if it's quick enough

	// shadowboot!
	/*InfoPrint("Attempting to shadowboot...\n");
	CreateShadowbootThread(SHADOWBOOT_FILE);*/

	/*InfoPrint("Launching xell...\n");
	if (LaunchXell() == FALSE) {
		InfoPrint("Error launching xell!\n");
	} */
	
	return TRUE;
}

EXTERN_C DWORD AnipPlayBootAnimation(HANDLE hModule, DWORD dwFlags) {
	ModuleHandle = hModule;

	InfoPrint("AnipPlayBootAnimation\n");
	Initialize();

	return 0;
}

EXTERN_C DWORD AnipEndAnimation(HANDLE hModule, DWORD dwReason, LPVOID lpReserved) {
	InfoPrint("AnipEndAnimation\n");
	// MountStuff();
	/*if (CPUStuff() == FALSE) {
		InfoPrint("Error writing CPU key to file!\n");
		return FALSE;
	}*/
	/*InfoPrint("Launching xell...\n");
	if (LaunchXell() == FALSE) {
		InfoPrint("Error launching xell!\n");
	}*/
	return 0;
}

EXTERN_C DWORD AnipSetLogo(HANDLE hModule, DWORD dwReason, LPVOID lpReserved) {
	InfoPrint("AnipSetLogo\n");
	return 0;
}