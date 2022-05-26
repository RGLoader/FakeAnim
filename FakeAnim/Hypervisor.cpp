#include "stdafx.h"

HvxCall HvxQuiesceProcessor(BYTE Reason) {
	__asm {
		li      r0, QUIESCE_PROCESSOR_SC
		sc
		blr
	}
}

HvxCall HvxPostOutput(BYTE bPostCode) {
	__asm {
		li      r0, POST_OUTPUT_SC
		sc
		blr
	}
}

HvxCall HvxShadowboot(PVOID pvSB, DWORD cbSB, WORD Flags) {
	__asm {
		li      r0, SHADOWBOOT_SC
		sc
		blr
	}
}

HvxCall HvxExpansionInstall(INT64 addr, DWORD size) {
	__asm {
		li      r0, EXPANSION_INST_SC
		sc
		blr
	}
}

HvxCall HvxExpansionCall(DWORD sig, QWORD Arg1, QWORD Arg2, QWORD Arg3, QWORD Arg4) {
	__asm {
		li      r0, EXPANSION_CALL_SC
		sc
		blr
	}
}