#include "Bootanim.h"

PVOID ExtendAllocation(PVOID pvAlloc, DWORD dwOffset, DWORD dwSize) {

}

PVOID Memory::memmove(PVOID pvDst, PVOID pvSrc, DWORD dwSize) {
	return MoveMemory(pvDst, pvSrc, dwSize);
}

PVOID Memory::memcpy(PVOID pvDst, PVOID pvSrc, DWORD dwSize) {
	return CopyMemory(pvDst, pvSrc, dwSize);
}

PVOID Memory::memset(PVOID pvDst, int iValue, DWORD dwSize) {
	return FillMemory(pvDst, dwSize, iValue);
}

DWORD Memory::memcmp(PVOID pvSrc1, PVOID pvSrc2, DWORD dwSize) {
	return RtlCompareMemory(pvSrc1, pvSrc2, dwSize);
}

PVOID Memory::zero(PVOID pvDst, DWORD dwSize) {
	return RtlZeroMemory(pvDst, dwSize);
}

BOOL Memory::equal(PVOID pvSrc1, PVOID pvSrc2, DWORD dwSize) {
	return RtlEqualMemory(pvSrc1, pvSrc2, dwSize);
}