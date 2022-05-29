#pragma once

class Utils {
	public:
		static void HexPrint(PBYTE pbData, DWORD dwSize);
		static DWORD StringLength(const PCHAR pcStr);
		static HRESULT MountPath(const char* szDrive, const char* szDevice, const char* sysStr);
		static HRESULT CreateSymbolicLink(const char* szDrive, const char* szDevice, BOOL both);
		static BOOL ApplyHVPatches(BYTE* patches, size_t size);
		static LONGLONG FileSize(LPCSTR lpFilename);
		static BOOL ReadFile(LPCSTR lpFilename, PVOID pvBuffer, DWORD dwSize);
		static BOOL WriteFile(LPCSTR lpFilename, PVOID pvBuffer, DWORD dwSize);
};