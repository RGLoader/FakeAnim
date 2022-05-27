#pragma once

#include <xtl.h>
#include <xboxmath.h>

#include "xkelib.h"
#include "Memory.h"
#include "Globals.h"
#include "HvExpansion.h"
#include "Shadowboot.h"
#include "Utilities.h"
#include "Hooks.h"
#include "Hypervisor.h"
#include "Bootanim.h"

#define DM_XBOX_HW_FLAG_HDD     0x00000020
#define DM_XBOX_HW_FLAG_TESTKIT 0x02000000

#define CPU_KEY_FILE "Hdd:\\cpukey.bin"
#define SHADOWBOOT_FILE "Hdd:\\shadowboot.bin"