#pragma once

#define DM_XBOX_HW_FLAG_HDD     0x00000020
#define DM_XBOX_HW_FLAG_TESTKIT 0x02000000

#define CPU_KEY_FILE "Hdd:\\cpukey.bin"
#define SHADOWBOOT_FILE "Hdd:\\shadowboot.bin"

namespace Bootanim {
	enum INITIALIZE_THREAD_EXIT_CODE : DWORD {
		SUCCESS = 0,
		EJECT_BAIL,
		MODEL_ERROR,
		PATCH_ERROR,
		PTE_ERROR,
		PATH_ERROR,
	};
}

// #define DEVKIT_TEST