#pragma once

#define EXPANSION_SIG 'HVPP'
#define STATUS_MEMORY_NOT_ALLOCATED ((NTSTATUS)0xC00000A0)
#define STATUS_CANT_FIND_SECTION    ((NTSTATUS)0xC8007005)

typedef enum {
	PeekBYTE = 0,
	PeekWORD = 1,
	PeekDWORD = 2,
	PeekQWORD = 3,
	PeekBytes = 4,
	PokeBYTE = 5,
	PokeWORD = 6,
	PokeDWORD = 7,
	PokeQWORD = 8,
	PokeBytes = 9,
	PeekSPR = 0xA,
	HvExecute = 0xC
};

typedef struct _HvPatchI {
	DWORD addr;
	DWORD size;
	BYTE data[1];
} HvPatchI, *PHvPatchI;

BYTE HvPeekBYTE(QWORD Address);
WORD HvPeekWORD(QWORD Address);
DWORD HvPeekDWORD(QWORD Address);
QWORD HvPeekQWORD(QWORD Address);
NTSTATUS HvPeekBytes(QWORD Address, PVOID Buffer, DWORD Size);
NTSTATUS HvPokeBYTE(QWORD Address, BYTE Value);
NTSTATUS HvPokeWORD(QWORD Address, WORD Value);
NTSTATUS HvPokeDWORD(QWORD Address, DWORD Value);
NTSTATUS HvPokeQWORD(QWORD Address, QWORD Value);
NTSTATUS HvPokeBytes(QWORD Address, const void* Buffer, DWORD Size);
QWORD HvReadFuseRow(int row);

BOOL ApplyHVPatches(PBYTE pbPatches, DWORD dwSize);
QWORD InstallExpansion();
void DumpHV();
BOOL LaunchXell();
VOID UARTWrite(DWORD dwData);
