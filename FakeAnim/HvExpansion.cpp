#include "stdafx.h"

using namespace std;

extern HANDLE ModuleHandle;

DWORD _declspec(naked) HvxExpansionInstall(INT64 addr, DWORD size)
{
	__asm {
		li      r0, EXPANSION_INST_SC
		sc
		blr
	}
}

QWORD __declspec(naked) HvxExpansionCall(DWORD sig, QWORD Arg1, QWORD Arg2, QWORD Arg3, QWORD Arg4)
{
	__asm {
		li      r0, EXPANSION_CALL_SC
		sc
		blr
	}
}

BYTE HvPeekBYTE(QWORD Address)
{
	return (BYTE)HvxExpansionCall(EXPANSION_SIG, PeekBYTE, Address, 0, 0);
}

WORD HvPeekWORD(QWORD Address)
{
	return (WORD)HvxExpansionCall(EXPANSION_SIG, PeekWORD, Address, 0, 0);
}

DWORD HvPeekDWORD(QWORD Address)
{
	return (DWORD)HvxExpansionCall(EXPANSION_SIG, PeekDWORD, Address, 0, 0);
}

QWORD HvPeekQWORD(QWORD Address)
{
	return HvxExpansionCall(EXPANSION_SIG, PeekQWORD, Address, 0, 0);
}

NTSTATUS HvPeekBytes(QWORD Address, PVOID Buffer, DWORD Size)
{
	NTSTATUS result = STATUS_MEMORY_NOT_ALLOCATED;
	VOID* allocData = XPhysicalAlloc(Size, MAXULONG_PTR, 0, PAGE_READWRITE);
	if (allocData != NULL)
	{
		QWORD daddr = (QWORD)((DWORD)MmGetPhysicalAddress(allocData) & 0xFFFFFFFF);
		ZeroMemory(allocData, Size);
		result = (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PeekBytes, Address, daddr, Size);
		if (NT_SUCCESS(result))
			memcpy(Buffer, allocData, Size);
		XPhysicalFree(allocData);
	} else
		Utils::InfoPrint("Error allocating buffer!\n");
	return result;
}

NTSTATUS HvPokeBYTE(QWORD Address, BYTE Value)
{
	return (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PokeBYTE, Address, Value, 0);
}

NTSTATUS HvPokeWORD(QWORD Address, WORD Value)
{
	return (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PokeWORD, Address, Value, 0);
}

NTSTATUS HvPokeDWORD(QWORD Address, DWORD Value)
{
	return (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PokeDWORD, Address, Value, 0);
}

NTSTATUS HvPokeQWORD(QWORD Address, QWORD Value)
{
	return (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PokeQWORD, Address, Value, 0);
}

NTSTATUS HvPokeBytes(QWORD Address, const void* Buffer, DWORD Size)
{
	NTSTATUS result = STATUS_MEMORY_NOT_ALLOCATED;
	VOID* allocData = XPhysicalAlloc(Size, MAXULONG_PTR, 0, PAGE_READWRITE);
	if (allocData != NULL)
	{
		QWORD daddr = (QWORD)((DWORD)MmGetPhysicalAddress(allocData) & 0xFFFFFFFF);
		memcpy(allocData, Buffer, Size);
		result = (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PokeBytes, Address, daddr, Size);
		XPhysicalFree(allocData);
	} else
		Utils::InfoPrint("Error allocating buffer!\n");
	return result;
}

QWORD HvReadFuseRow(int row)
{
	if (row < 12)
	{
		QWORD addr;
		addr = 0x8000020000020000ULL | (row * 0x200);
		return HvPeekQWORD(addr);
	}
	return 0;
}

QWORD FixHVOffset(QWORD qwOff)
{
	if (qwOff > 0x10000)
	{
		if (qwOff > 0x30000)
			qwOff |= 0x600000000;
		else if (qwOff > 0x20000)
			qwOff |= 0x400000000;
		else
			qwOff |= 0x200000000;
	}
	return qwOff;
}

BOOL ApplyHVPatches(BYTE* patches, size_t size)
{
	DWORD offset = 0;
	BYTE* ppatch = patches;
	while (offset < size)
	{
		PHvPatchI patchi = (PHvPatchI)ppatch;
		QWORD paddr = (QWORD)(patchi->addr);
		if (patchi->addr == 0xFFFFFFFF)
			return TRUE;
		HvPokeBytes(FixHVOffset(paddr), patchi->data, patchi->size * 4);
		offset = offset + 8 + patchi->size * 4;
		ppatch = &patches[offset];
	}
	return FALSE;
}

DWORD InstallExpansion() {
	PVOID pSecData;
	ULONG pSecSize;
	if (!XGetModuleSection(ModuleHandle, "exp", &pSecData, &pSecSize)) {
		Utils::InfoPrint("Error getting \"exp\" section!\n");
		return NULL;
	}

	BYTE* allocData = (BYTE*)XPhysicalAlloc(0x1000, MAXULONG_PTR, 0, PAGE_READWRITE);
	ZeroMemory(allocData, 0x1000);
	memcpy(allocData, pSecData, pSecSize);
	QWORD addr = (QWORD)MmGetPhysicalAddress(allocData);
	DWORD ret = HvxExpansionInstall(addr, 0x1000);
	XPhysicalFree(allocData);
	return ret;
}

BOOL LaunchXell() {
	PVOID pSecData;
	ULONG pSecSize;
	if (!XGetModuleSection(ModuleHandle, "xell", &pSecData, &pSecSize)) {
		Utils::InfoPrint("Error getting \"xell\" section!\n");
		return FALSE;
	}

	PBYTE allocData = (PBYTE)XPhysicalAlloc(pSecSize, MAXULONG_PTR, 0, MEM_LARGE_PAGES | PAGE_READWRITE | PAGE_NOCACHE);
	ZeroMemory(allocData, pSecSize);
	memcpy(allocData, pSecData, pSecSize);
	UINT64 len = 0ULL + (((pSecSize + 3) / 4) & 0xFFFFFFFF);
	UINT64 src = 0x8000000000000000ULL;
	src = src + ((DWORD)MmGetPhysicalAddress(allocData));
	HvxExpansionCall(EXPANSION_SIG, HvExecute, 0x800000001C040000, src, len);
	XPhysicalFree(allocData);

	return TRUE;
}
