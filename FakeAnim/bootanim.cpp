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

BOOL CPUStuff(BOOL bWriteToFile) {
	Utils::InfoPrint("CPU key: ");
	BYTE CPUKeyHV[0x10];
	HvPeekBytes(0x20, CPUKeyHV, 0x10);
	Utils::HexPrint(CPUKeyHV, 0x10);
	DbgPrint("\n");

	if (!bWriteToFile)
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

typedef void(*KISHADOWBOOT)(DWORD dwAddr, DWORD dw1, DWORD dw2);
KISHADOWBOOT KiShadowbootOrig;

void KiShadowBootHook(DWORD dwAddr, DWORD dw1, DWORD dw2) {
	KiShadowbootOrig(dwAddr, dw1, dw2);
}

BOOL HookStuff() {
	KiShadowbootOrig = reinterpret_cast<KISHADOWBOOT>(HookFunctionStub((PDWORD)0x80085FA8, KiShadowBootHook));

	return TRUE;
}

BOOL PatchShadowbootPath() {
	PSTRING dwHd0StrPtr;
	// DWORD* dwExpTryToShadowBootPtr;

	const CHAR Hd0BufferOld[] = "\\Device\\Harddisk0\\Partition1\\xboxromtw2d.bin";
	// needs to be equal or shorter than Hd0BufferOld
	const CHAR Hd0BufferNew[] = "\\Device\\Harddisk0\\Partition1\\shadowboot.bin";

	DWORD Hd0BuffLookup[] = {
		0x80040514  // correct for my test kit
	};

	for (DWORD i = 0; i < (sizeof(Hd0BuffLookup) / sizeof(Hd0BuffLookup[0])); i++) {
		PSTRING hd0Str = (PSTRING)Hd0BuffLookup[i];

		// check if already patched
		if (RtlEqualMemory(hd0Str->Buffer, Hd0BufferNew, hd0Str->Length)) {
			dwHd0StrPtr = (PSTRING)Hd0BuffLookup[i];
			Utils::InfoPrint("Hd0 buffer already patched, skipping...\n");
			break;
		}

		// check for buffer
		if (RtlEqualMemory(hd0Str->Buffer, Hd0BufferOld, hd0Str->Length)) {
			dwHd0StrPtr = (PSTRING)Hd0BuffLookup[i];
			Utils::InfoPrint("Patching hd0 buffer...\n");
			ZeroMemory(hd0Str->Buffer, hd0Str->MaximumLength);
			hd0Str->Length = Utils::StringLength((PCHAR)Hd0BufferNew);
			hd0Str->MaximumLength = Utils::StringLength((PCHAR)Hd0BufferNew) + 1;
			CopyMemory(hd0Str->Buffer, Hd0BufferNew, Utils::StringLength((PCHAR)Hd0BufferNew));  // we want it at the original location
			Utils::InfoPrint("Shadowboot Path: \"%s\" @ 0x%X\n", hd0Str->Buffer, hd0Str->Buffer);
			break;
		}
	}

	return TRUE;
}

void Initialize() {
	// check power reason
	BYTE reason[0x10];
	ZeroMemory(reason, 0x10);
	HalGetPowerUpCause(reason);
	if (reason[1] == SMC_PWR_REAS_12_EJECT) {
		Utils::InfoPrint("Booted with eject button, bailing...\n");
		HvxPostOutput(0x7A);
		ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::EJECT_BAIL);
		return;
	}

#ifndef DEVKIT
	if (XboxHardwareInfo->Flags & DM_XBOX_HW_FLAG_TESTKIT != DM_XBOX_HW_FLAG_TESTKIT) {
		Utils::InfoPrint("This was designed for test kits, bailing...\n");
		HvxPostOutput(0x7B);
		ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::MODEL_ERROR);
		return;
	}

	if (XboxKrnlVersion->Build != 12387) {
		Utils::InfoPrint("This was designed for test kits running 11775.3/12387, bailing...\n");
		HvxPostOutput(0x7C);
		ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::KRNL_VERSION_ERROR);
		return;
	}
#endif

	while (XboxHardwareInfo->Flags & DM_XBOX_HW_FLAG_HDD != DM_XBOX_HW_FLAG_HDD) {
		Utils::InfoPrint("Sleeping until the SATA driver is up...\n");
		Sleep(100);
	}

	Utils::InfoPrint("HDD initialized, resuming...\n");

	// create mounts
	if (MountStuff() == FALSE) {
		Utils::InfoPrint("Error creating symlinks!\n");
		HvxPostOutput(0x7D);
		ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::MOUNT_ERROR);
		return;
	}

	// check if the expansion is already installed
	if (ExpansionStuff() == FALSE) {
		Utils::InfoPrint("Error installing expansion!\n");
		HvxPostOutput(0x7E);
		ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::EXP_ERROR);
		return;
	}

#ifndef DEVKIT
	// memory protection patches
	if (PatchStuff() == FALSE) {
		Utils::InfoPrint("Error installing patches!\n");
		HvxPostOutput(0x7F);
		ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::PATCH_ERROR);
		return;
	}

	// refresh PTE tables
	if (FixCache(4) == FALSE) {
		Utils::InfoPrint("Error fixing PTE tables!\n");
		HvxPostOutput(0x80);
		ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::PTE_ERROR);
		return;
	}

	// patch hd0 buffer
	if (PatchShadowbootPath() == FALSE) {
		Utils::InfoPrint("Error patching shadowboot path!\n");
		HvxPostOutput(0x81);
		ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::PATH_ERROR);
		return;
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

	HvxPostOutput(0x82);
	ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::SUCCESS);

	// shadowboot will happen automatically right after this if it's quick enough
}

EXTERN_C DWORD AnipPlayBootAnimation(HANDLE hModule, DWORD dwFlags) {
	ModuleHandle = hModule;

	Utils::InfoPrint("AnipPlayBootAnimation\n");

	// no need to create a thread, this is called in it's own thread
	Initialize();

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