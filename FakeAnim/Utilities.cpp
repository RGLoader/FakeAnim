#include "Bootanim.h"

void Utils::HexPrint(PBYTE pbData, size_t stLen) {
	for (int i = 0; i < stLen; i++) {
		DbgPrint("%02X", pbData[i]);
	}
}

DWORD Utils::StringLength(const PCHAR pcStr) {
	PCHAR pcStri = pcStr;
	DWORD dwSize = 0;
	while (*pcStri != 0) {
		dwSize += sizeof(CHAR);
		pcStri += sizeof(CHAR);
	}
	return dwSize;
}

HRESULT Utils::MountPath(const char* szDrive, const char* szDevice, const char* sysStr)
{
	STRING DeviceName, LinkName;
	CHAR szDestinationDrive[MAX_PATH];
	RtlSnprintf(szDestinationDrive, MAX_PATH, sysStr, szDrive);
	RtlInitAnsiString(&DeviceName, szDevice);
	RtlInitAnsiString(&LinkName, szDestinationDrive);
	ObDeleteSymbolicLink(&LinkName);
	return (HRESULT)ObCreateSymbolicLink(&LinkName, &DeviceName);
}

HRESULT Utils::CreateSymbolicLink(const char* szDrive, const char* szDevice, BOOL both) {
	HRESULT res = -1;
	if (both) {
		DbgPrint("Mounting as both!\n");
		res = Utils::MountPath(szDrive, szDevice, OBJ_SYS_STRING);
		res |= Utils::MountPath(szDrive, szDevice, OBJ_USR_STRING);
	} else {
		if (KeGetCurrentProcessType() == PROC_SYSTEM) {
			DbgPrint("Mounting as system!\n");
			res = Utils::MountPath(szDrive, szDevice, OBJ_SYS_STRING);
		} else {
			DbgPrint("Mounting as user!\n");
			res = Utils::MountPath(szDrive, szDevice, OBJ_USR_STRING);
		}
	}
	return res;
}

LONGLONG Utils::FileSize(LPCSTR lpFilename)
{
	HANDLE hFile = CreateFile(lpFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;
	LARGE_INTEGER liSize;
	BOOL bRet = ::GetFileSizeEx(hFile, &liSize);
	CloseHandle(hFile);
	if (!bRet)
		return -1;
	return liSize.QuadPart;
}

BOOL Utils::ReadFile(LPCSTR lpFilename, PVOID pvBuffer, DWORD dwSize)
{
	HANDLE hFile = CreateFile(lpFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		// InfoPrint("CreateFile: %04X\n", GetLastError());
		return FALSE;
	}
	DWORD dwBytesRead;
	::ReadFile(hFile, pvBuffer, dwSize, &dwBytesRead, NULL);
	CloseHandle(hFile);
	if (dwBytesRead <= 0)
		return FALSE;
	return TRUE;
}

BOOL Utils::WriteFile(LPCSTR lpFilename, PVOID pvBuffer, DWORD dwSize)
{
	HANDLE hFile = CreateFile(lpFilename, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		// InfoPrint("CreateFile: %04X\n", GetLastError());
		return FALSE;
	}
	DWORD dwBytesWritten;
	::WriteFile(hFile, pvBuffer, dwSize, &dwBytesWritten, NULL);
	CloseHandle(hFile);
	if (dwBytesWritten != dwSize)
		return FALSE;
	return TRUE;
}