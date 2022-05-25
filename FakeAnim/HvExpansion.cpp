#include "stdafx.h"

using namespace std;

extern HANDLE ModuleHandle;

BYTE HvPeekBYTE(QWORD qwAddr)
{
	return (BYTE)HvxExpansionCall(EXPANSION_SIG, PeekBYTE, qwAddr, 0, 0);
}

WORD HvPeekWORD(QWORD qwAddr)
{
	return (WORD)HvxExpansionCall(EXPANSION_SIG, PeekWORD, qwAddr, 0, 0);
}

DWORD HvPeekDWORD(QWORD qwAddr)
{
	return (DWORD)HvxExpansionCall(EXPANSION_SIG, PeekDWORD, qwAddr, 0, 0);
}

QWORD HvPeekQWORD(QWORD qwAddr)
{
	return HvxExpansionCall(EXPANSION_SIG, PeekQWORD, qwAddr, 0, 0);
}

NTSTATUS HvPeekBytes(QWORD qwAddr, PVOID pvBuffer, DWORD dwSize) {
	NTSTATUS result = STATUS_MEMORY_NOT_ALLOCATED;
	VOID* allocData = XPhysicalAlloc(dwSize, MAXULONG_PTR, 0, PAGE_READWRITE);
	if (allocData != NULL)
	{
		QWORD daddr = (QWORD)((DWORD)MmGetPhysicalAddress(allocData) & 0xFFFFFFFF);
		ZeroMemory(allocData, dwSize);
		result = (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PeekBytes, qwAddr, daddr, dwSize);
		if (NT_SUCCESS(result))
			CopyMemory(pvBuffer, allocData, dwSize);
		XPhysicalFree(allocData);
	} else
		Utils::InfoPrint("Error allocating buffer!\n");
	return result;
}

NTSTATUS HvPokeBYTE(QWORD qwAddr, BYTE bValue) {
	return (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PokeBYTE, qwAddr, bValue, 0);
}

NTSTATUS HvPokeWORD(QWORD qwAddr, WORD wValue) {
	return (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PokeWORD, qwAddr, wValue, 0);
}

NTSTATUS HvPokeDWORD(QWORD qwAddr, DWORD dwValue) {
	return (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PokeDWORD, qwAddr, dwValue, 0);
}

NTSTATUS HvPokeQWORD(QWORD qwAddr, QWORD qwValue) {
	return (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PokeQWORD, qwAddr, qwValue, 0);
}

NTSTATUS HvPokeBytes(QWORD qwAddr, const void* vpBuffer, DWORD dwSize) {
	NTSTATUS result = STATUS_MEMORY_NOT_ALLOCATED;
	VOID* allocData = XPhysicalAlloc(dwSize, MAXULONG_PTR, 0, PAGE_READWRITE);
	if (allocData != NULL)
	{
		QWORD daddr = (QWORD)((DWORD)MmGetPhysicalAddress(allocData) & 0xFFFFFFFF);
		CopyMemory(allocData, vpBuffer, dwSize);
		result = (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PokeBytes, qwAddr, daddr, dwSize);
		XPhysicalFree(allocData);
	} else
		Utils::InfoPrint("Error allocating buffer!\n");
	return result;
}

QWORD HvReadFuseRow(int row) {
	if (row < 12)
	{
		QWORD addr;
		addr = 0x8000020000020000ULL | (row * 0x200);
		return HvPeekQWORD(addr);
	}
	return 0;
}

QWORD FixHVOffset(QWORD qwOffset) {
	if (qwOffset > 0x10000)
	{
		if (qwOffset > 0x30000)
			qwOffset |= 0x600000000;
		else if (qwOffset > 0x20000)
			qwOffset |= 0x400000000;
		else
			qwOffset |= 0x200000000;
	}
	return qwOffset;
}

BOOL ApplyHVPatches(PBYTE pbPatches, DWORD dwSize) {
	DWORD dwOffset = 0;
	PBYTE pbPatch = pbPatches;
	while (dwOffset < dwSize)
	{
		PHvPatchI patchi = (PHvPatchI)pbPatch;
		QWORD paddr = (QWORD)(patchi->addr);
		if (patchi->addr == 0xFFFFFFFF)
			return TRUE;
		HvPokeBytes(FixHVOffset(paddr), patchi->data, patchi->size * 4);
		dwOffset = dwOffset + 8 + patchi->size * 4;
		pbPatch = &pbPatches[dwOffset];
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

	BYTE* pbAlloc = (BYTE*)XPhysicalAlloc(0x1000, MAXULONG_PTR, 0, PAGE_READWRITE);
	ZeroMemory(pbAlloc, 0x1000);
	CopyMemory(pbAlloc, pSecData, pSecSize);
	QWORD qwAddr = (QWORD)MmGetPhysicalAddress(pbAlloc);
	DWORD dwRet = HvxExpansionInstall(qwAddr, 0x1000);
	XPhysicalFree(pbAlloc);
	return dwRet;
}

BOOL LaunchXell() {
	PVOID pSecData;
	ULONG pSecSize;
	if (!XGetModuleSection(ModuleHandle, "xell", &pSecData, &pSecSize)) {
		Utils::InfoPrint("Error getting \"xell\" section!\n");
		return FALSE;
	}

	PBYTE pbAlloc = (PBYTE)XPhysicalAlloc(pSecSize, MAXULONG_PTR, 0, MEM_LARGE_PAGES | PAGE_READWRITE | PAGE_NOCACHE);
	ZeroMemory(pbAlloc, pSecSize);
	CopyMemory(pbAlloc, pSecData, pSecSize);
	UINT64 len = 0ULL + (((pSecSize + 3) / 4) & 0xFFFFFFFF);
	UINT64 src = 0x8000000000000000ULL;
	src = src + ((DWORD)MmGetPhysicalAddress(pbAlloc));
	HvxExpansionCall(EXPANSION_SIG, HvExecute, 0x800000001C040000, src, len);
	XPhysicalFree(pbAlloc);

	return TRUE;
}
