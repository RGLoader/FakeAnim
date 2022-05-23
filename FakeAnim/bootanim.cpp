// FakeAnim.cpp : Defines the entry point for the application.

#include "stdafx.h"

using namespace std;

HANDLE ModuleHandle = NULL;

BOOL MountStuff() {
	Utils::InfoPrint("Creating mounts...\n");
	 if (Utils::CreateSymbolicLink("Hdd:", "\\Device\\Harddisk0\\Partition1", TRUE) != ERROR_SUCCESS) {
		 Utils::InfoPrint("Error creating symlinks!\n");
		 return FALSE;
	 }
	 Utils::InfoPrint("Done!\n");

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

	Utils::InfoPrint("Checking if the HVPP expansion is installed...\n");
	if (HvPeekWORD(0) != 0x5E4E) {
		// install signed and encrypted HVPP expansion
		Utils::InfoPrint("Installing HVPP expansion...\n");
		DWORD ret = InstallExpansion();
		if (ret != ERROR_SUCCESS) {
			Utils::InfoPrint("InstallExpansion: %04X\n", ret);
			return FALSE;
		}
		Utils::InfoPrint("Done!\n");
	} else
		Utils::InfoPrint("Expansion is already installed, skipping...\n");

	return TRUE;
}

BOOL PatchStuff() {
	Utils::InfoPrint("Applying HV patches...\n");
	
	PVOID pSecData;
	ULONG pSecSize;
	if (!XGetModuleSection(ModuleHandle, "patches", &pSecData, &pSecSize)) {
		Utils::InfoPrint("Error getting \"patches\" section!\n");
		return FALSE;
	}

	if (ApplyHVPatches((PBYTE)pSecData, pSecSize) == FALSE) {
		Utils::InfoPrint("Error applying patches!\n");
		return FALSE;
	}
	Utils::InfoPrint("Done!\n");

	return TRUE;
}

BOOL CPUStuff(BOOL writeToFile) {
	Utils::InfoPrint("CPU key: ");
	BYTE CPUKeyHV[0x10];
	HvPeekBytes(0x20, CPUKeyHV, 0x10);
	Utils::HexPrint(CPUKeyHV, 0x10);
	DbgPrint("\n");

	if (!writeToFile)
		return TRUE;

	Utils::InfoPrint("Writing CPU key to file...\n");
	if (!Utils::WriteFile(CPU_KEY_FILE, CPUKeyHV, 0x10)) {
		// InfoPrint("Error writing CPU key to file!\n");
		return FALSE;
	}
	Utils::InfoPrint("Done!\n");

	return TRUE;
}

BOOL FixCache(DWORD dwMb) {
	Utils::InfoPrint("Allocating %lu MB to fix PTE cache...\n", dwMb);
	DWORD dwSize = dwMb * 1024 * 1024;
	PBYTE pbTest = (PBYTE)XPhysicalAlloc(dwSize, MAXULONG_PTR, 0, PAGE_READWRITE);
	XeCryptRandom(pbTest, dwSize);
	XPhysicalFree(pbTest);
	Utils::InfoPrint("Done!\n");

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
			Utils::InfoPrint("Hd0 buffer already patched, skipping...\n");
			break;
		}

		// check for buffer
		if (memcmp(hd0Str->Buffer, Hd0BufferOld, hd0Str->Length) == 0) {
			dwHd0StrPtr = (PSTRING)Hd0BuffLookup[i];
			Utils::InfoPrint("Patching hd0 buffer...\n");
			ZeroMemory(hd0Str->Buffer, hd0Str->MaximumLength);
			hd0Str->Length = strlen(Hd0BufferNew);
			hd0Str->MaximumLength = strlen(Hd0BufferNew) + 1;
			memcpy(hd0Str->Buffer, Hd0BufferNew, strlen(Hd0BufferNew));  // we want it at the original location
			Utils::InfoPrint("Shadowboot Path: \"%s\" @ 0x%X\n", hd0Str->Buffer, hd0Str->Buffer);
			break;
		}
	}

	return TRUE;
}

void Initialize() {  // HANDLE hModule) {
	// check power reason
	BYTE reason[0x10];
	ZeroMemory(reason, 0x10);
	HalGetPowerUpCause(reason);
	if (reason[1] == SMC_PWR_REAS_12_EJECT) {
		Utils::InfoPrint("Booted with eject button, bailing...\n");
		ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::EJECT_BAIL);
	}

#ifndef DEVKIT_TEST
	if (XboxHardwareInfo->Flags & DM_XBOX_HW_FLAG_TESTKIT != DM_XBOX_HW_FLAG_TESTKIT) {
		Utils::InfoPrint("This was designed for test kits, bailing...\n");
		ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::MODEL_ERROR);
	}
#endif

	while (XboxHardwareInfo->Flags & DM_XBOX_HW_FLAG_HDD != DM_XBOX_HW_FLAG_HDD) {
		Utils::InfoPrint("Sleeping until the SATA driver is up...\n");
		Sleep(100);
	}

	Utils::InfoPrint("HDD initialized, resuming...\n");

	MountStuff();

	// check if the expansion is already installed
	if (ExpansionStuff() == FALSE) {
		Utils::InfoPrint("Error installing expansion!\n");
		ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::SUCCESS);
	}

#ifndef DEVKIT_TEST
	// memory protection patches
	if (PatchStuff() == FALSE) {
		Utils::InfoPrint("Error installing patches!\n");
		ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::PATCH_ERROR);
	}

	// refresh PTE tables
	if (FixCache(4) == FALSE) {
		Utils::InfoPrint("Error fixing PTE tables!\n");
		ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::PTE_ERROR);
	}

	// patch hd0 buffer
	if (PatchShadowbootPath() == FALSE) {
		Utils::InfoPrint("Error patching shadowboot path!\n");
		ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::PATH_ERROR);
	}
#else
	// CPU key
	/*if (CPUStuff(TRUE) == FALSE) {
		Utils::InfoPrint("Error writing CPU key to file!\n");
		return FALSE;
	}*/

	// shadowboot!
	// Utils::InfoPrint("Attempting to shadowboot...\n");
	// CreateShadowbootThread(SHADOWBOOT_FILE);
#endif

	ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::SUCCESS);

	// shadowboot will happen automatically right after this if it's quick enough
}

EXTERN_C DWORD AnipPlayBootAnimation(HANDLE hModule, DWORD dwFlags) {
	ModuleHandle = hModule;

	Utils::InfoPrint("AnipPlayBootAnimation\n");

	HANDLE hThread;
	DWORD dwThreadId;
	ExCreateThread(&hThread, 0, &dwThreadId, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)Initialize, NULL, 2);
	XSetThreadProcessor(hThread, 4);
	SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
	ResumeThread(hThread);

	return 0;
}

EXTERN_C DWORD AnipEndAnimation(HANDLE hModule, DWORD dwReason, LPVOID lpReserved) {
	Utils::InfoPrint("AnipEndAnimation\n");
	return 0;
}

EXTERN_C DWORD AnipSetLogo(HANDLE hModule, DWORD dwReason, LPVOID lpReserved) {
	Utils::InfoPrint("AnipSetLogo\n");
	return 0;
}