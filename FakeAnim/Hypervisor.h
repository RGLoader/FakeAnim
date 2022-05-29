#pragma once

#define HV_PTE_TABLE_POINTER 0x44

#define HvxCall __declspec(naked) QWORD

#define QUIESCE_PROCESSOR_SC 0x2
#define POST_OUTPUT_SC       0xD
#define SHADOWBOOT_SC        0x21
#define EXPANSION_INST_SC    0x70
#define EXPANSION_CALL_SC    0x71

QWORD HvxQuiesceProcessor(BYTE bReason);
QWORD HvxPostOutput(BYTE bPostCode);
QWORD HvxShadowboot(PVOID pvData, DWORD dwSize, WORD wFlags);
QWORD HvxExpansionInstall(PVOID pvAddr, DWORD dwSize);
QWORD HvxExpansionCall(DWORD sig, QWORD Arg1, QWORD Arg2, QWORD Arg3, QWORD Arg4);