#pragma once

class Memory {
	public:
		PVOID memmove(PVOID pvDst, PVOID pvSrc, DWORD dwSize);
		PVOID memcpy(PVOID pvDst, PVOID pvSrc, DWORD dwSize);
		PVOID memset(PVOID pvDst, int iValue, DWORD dwSize);
		DWORD memcmp(PVOID pvSrc1, PVOID pvSrc2, DWORD dwSize);
		PVOID zero(PVOID pvDst, DWORD dwSize);
		BOOL equal(PVOID pvSrc1, PVOID pvSrc2, DWORD dwSize);
};