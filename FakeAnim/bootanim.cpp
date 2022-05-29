#include "Bootanim.h"

using namespace std;

BOOL BootedWithEject() {
	BYTE reason[0x10];
	ZeroMemory(reason, 0x10);
	HalGetPowerUpCause(reason);
	if(reason[1] == SMC_PWR_REAS_12_EJECT)
		return TRUE;
	return FALSE;
}

BOOL MountStuff() {
	DbgPrint("Creating mounts...\n");
	 if (Utils::CreateSymbolicLink("Hdd:", "\\Device\\Harddisk0\\Partition1", TRUE) != ERROR_SUCCESS) {
		 DbgPrint("Error creating symlinks!\n");
		 return FALSE;
	 }
	 DbgPrint("Done!\n");

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

	DbgPrint("Checking if the HVPP expansion is installed...\n");
	if (HvPeekWORD(0) != 0x5E4E) {
		// install signed and encrypted HVPP expansion
		DbgPrint("Installing HVPP expansion...\n");
		QWORD qwRet = InstallExpansion();
		if ((qwRet & 0xFFFFFFFF) != ERROR_SUCCESS) {
			if(HvPeekWORD(0) != 0x5E4E)
				return FALSE;
		}
		DbgPrint("Done!\n");
	} else
		DbgPrint("Expansion is already installed, skipping...\n");

	return TRUE;
}

BOOL PatchStuff() {
	DbgPrint("Applying HV patches...\n");
	
	PVOID pSecData;
	ULONG pSecSize;
	if (!XGetModuleSection(Globals::ModuleHandle, "patches", &pSecData, &pSecSize)) {
		DbgPrint("Error getting \"patches\" section!\n");
		return FALSE;
	}

	if (!ApplyHVPatches((PBYTE)pSecData, pSecSize)) {
		DbgPrint("Error applying patches!\n");
		return FALSE;
	}
	DbgPrint("Done!\n");

	return TRUE;
}

BOOL CPUStuff(BOOL bWriteToFile) {
	DbgPrint("CPU key: ");
	BYTE CPUKeyHV[0x10];
	HvPeekBytes(0x20, CPUKeyHV, 0x10);
	Utils::HexPrint(CPUKeyHV, 0x10);
	DbgPrint("\n");

	if (!bWriteToFile)
		return TRUE;

	DbgPrint("Writing CPU key to file...\n");
	if (!Utils::WriteFile(CPU_KEY_FILE, CPUKeyHV, 0x10)) {
		// InfoPrint("Error writing CPU key to file!\n");
		return FALSE;
	}
	DbgPrint("Done!\n");

	return TRUE;
}

BOOL FixCache(DWORD dwMb) {
	DbgPrint("Allocating %lu MB to fix PTE cache...\n", dwMb);
	DWORD dwSize = dwMb * 1024 * 1024;
	PBYTE pbTest = (PBYTE)XPhysicalAlloc(dwSize, MAXULONG_PTR, 0, PAGE_READWRITE);
	XeCryptRandom(pbTest, dwSize);
	XPhysicalFree(pbTest);
	DbgPrint("Done!\n");

	return TRUE;
}

BOOL PatchShadowbootPath() {
	const CHAR Hd0BufferOld[] = "\\Device\\Harddisk0\\Partition1\\xboxromtw2d.bin";
	// needs to be equal or shorter than Hd0BufferOld
	const CHAR Hd0BufferNew[] = "\\Device\\Harddisk0\\Partition1\\shadowboot.bin";

	DWORD Hd0BuffLookup[] = {
		0x80040514  // correct for my test kit
	};

	PSTRING hd0Str = (PSTRING)0x80040514;
	if(RtlEqualMemory(hd0Str->Buffer, Hd0BufferOld, hd0Str->Length)) {
		hd0Str->Length = Utils::StringLength((PCHAR)Hd0BufferNew);
		hd0Str->MaximumLength = hd0Str->Length + 1;
		ZeroMemory(hd0Str->Buffer, hd0Str->MaximumLength);
		CopyMemory(hd0Str->Buffer, Hd0BufferNew, hd0Str->Length);
		DbgPrint("Shadowboot Path: \"%s\" @ 0x%04X\n", hd0Str->Buffer, (DWORD)hd0Str->Buffer);
		doSync(hd0Str);
	}

	//PSTRING dwHd0StrPtr;
	//for (DWORD i = 0; i < (sizeof(Hd0BuffLookup) / sizeof(DWORD)); i++) {
	//	PSTRING hd0Str = (PSTRING)Hd0BuffLookup[i];

	//	// check if already patched
	//	if (RtlEqualMemory(hd0Str->Buffer, Hd0BufferNew, hd0Str->Length)) {
	//		dwHd0StrPtr = (PSTRING)Hd0BuffLookup[i];
	//		DbgPrint("Hd0 buffer already patched, skipping...\n");
	//		break;
	//	}

	//	// check for buffer
	//	if (RtlEqualMemory(hd0Str->Buffer, Hd0BufferOld, hd0Str->Length)) {
	//		dwHd0StrPtr = (PSTRING)Hd0BuffLookup[i];
	//		DbgPrint("Patching hd0 buffer...\n");
	//		ZeroMemory(hd0Str->Buffer, hd0Str->MaximumLength);
	//		hd0Str->Length = Utils::StringLength((PCHAR)Hd0BufferNew);
	//		hd0Str->MaximumLength = Utils::StringLength((PCHAR)Hd0BufferNew) + 1;
	//		CopyMemory(hd0Str->Buffer, Hd0BufferNew, Utils::StringLength((PCHAR)Hd0BufferNew));  // we want it at the original location
	//		// DbgPrint("Shadowboot Path: \"%s\" @ 0x%04X\n", hd0Str->Buffer, (DWORD)hd0Str->Buffer);
	//		DbgPrint("Shadowboot Path: \"%s\" @ 0x%04X\n", hd0Str->Buffer, (DWORD)hd0Str->Buffer);
	//		doSync(hd0Str);
	//		break;
	//	}
	//}

	return TRUE;
}

void Initialize() {
	if ((XboxHardwareInfo->Flags & DM_XBOX_HW_FLAG_TESTKIT) != DM_XBOX_HW_FLAG_TESTKIT) {
		DbgPrint("This was designed for test kits, bailing...\n");
		// HvxPostOutput(0x7B);
		// ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::MODEL_ERROR);
		return;
	}

	if (XboxKrnlVersion->Build != 12387) {
		DbgPrint("This was designed for test kits running 11775.3/12387, bailing...\n");
		// HvxPostOutput(0x7C);
		// ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::KRNL_VERSION_ERROR);
		return;
	}

	/*while ((XboxHardwareInfo->Flags & DM_XBOX_HW_FLAG_HDD) != DM_XBOX_HW_FLAG_HDD) {
		DbgPrint("Waiting until the SATA driver is up...\n");
	}

	DbgPrint("HDD initialized, resuming...\n");*/

	// create mounts
	//if (!MountStuff()) {
	//	DbgPrint("Error creating symlinks!\n");
	//	// HvxPostOutput(0x7D);
	//	// ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::MOUNT_ERROR);
	//	return;
	//}

	// check if the expansion is already installed
	//if (!ExpansionStuff()) {
	//	DbgPrint("Error installing expansion!\n");
	//	// HvxPostOutput(0x7E);
	//	// ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::EXP_ERROR);
	//	return;
	//}

	InstallExpansion();

	// memory protection patches
	if (!PatchStuff()) {
		DbgPrint("Error installing patches!\n");
		// HvxPostOutput(0x7F);
		// ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::PATCH_ERROR);
		return;
	}

	//// refresh PTE tables
	if (!FixCache(16)) {
		DbgPrint("Error fixing PTE tables!\n");
		// HvxPostOutput(0x80);
		// ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::PTE_ERROR);
		return;
	}

	//// patch hd0 buffer
	if(!PatchShadowbootPath()) {
		DbgPrint("Error patching shadowboot path!\n");
		// HvxPostOutput(0x81);
		// ExTerminateThread(Bootanim::INITIALIZE_THREAD_EXIT_CODE::PATH_ERROR);
		return;
	}
}

EXTERN_C DWORD AniPlayBootAnimation(HANDLE hModule, DWORD dwFlags) {
	if(BootedWithEject()) {
		DbgPrint("Booted with eject button, bailing...\n");
		return 0;
	}

	Globals::ModuleHandle = hModule;

	DbgPrint("AnipPlayBootAnimation\n");

	Initialize();

	return 0;
}

EXTERN_C DWORD AniEndAnimation(END_ANIMATION_TYPE eat) {
	if(BootedWithEject()) {
		DbgPrint("Booted with eject button, bailing...\n");
		return 0;
	}

	if(eat == ANIM_BLOCK) {
		DbgPrint("AniEndAnimation - Block\n");
	} else if(eat == ANIM_TERMINATE) {
		DbgPrint("AniEndAnimation - Terminate\n");
	}

	return 0;
}

EXTERN_C DWORD AniSetLogo(DWORD dw1, DWORD dw2, DWORD dw3) {
	if(BootedWithEject()) {
		DbgPrint("Booted with eject button, bailing...\n");
		return 0;
	}

	DbgPrint("AnipSetLogo\n");

	return 0;
}