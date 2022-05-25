#pragma once

#define HvxCall __declspec(naked) QWORD

#define QUIESCE_PROCESSOR_SC 0x2
#define POST_OUTPUT_SC       0xD
#define SHADOWBOOT_SC        0x21
#define EXPANSION_INST_SC    0x70
#define EXPANSION_CALL_SC    0x71

QWORD HvxQuiesceProcessor(BYTE Reason);
QWORD HvxPostOutput(DWORD dwPostCode);
QWORD HvxShadowboot(PVOID pvSB, DWORD cbSB, WORD Flags);
QWORD HvxExpansionInstall(INT64 addr, DWORD size);
QWORD HvxExpansionCall(DWORD sig, QWORD Arg1, QWORD Arg2, QWORD Arg3, QWORD Arg4);