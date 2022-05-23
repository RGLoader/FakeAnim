#include "stdafx.h"

void Utils::InfoPrint(const char* data, ...) {
	va_list argp;
	char temp[512];

	DbgPrint("[FakeAnim] ");
	va_start(argp, data);
	RtlSnprintf(temp, 512, data, argp);
	va_end(argp);
	DbgPrint(temp);
}

void Utils::HexPrint(PBYTE pbData, size_t stLen) {
	for (int i = 0; i < stLen; i++) {
		DbgPrint("%02X", pbData[i]);
	}
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
		InfoPrint("Mounting as both!\n");
		res = Utils::MountPath(szDrive, szDevice, OBJ_SYS_STRING);
		res |= Utils::MountPath(szDrive, szDevice, OBJ_USR_STRING);
	} else {
		if (KeGetCurrentProcessType() == PROC_SYSTEM) {
			InfoPrint("Mounting as system!\n");
			res = Utils::MountPath(szDrive, szDevice, OBJ_SYS_STRING);
		} else {
			InfoPrint("Mounting as user!\n");
			res = Utils::MountPath(szDrive, szDevice, OBJ_USR_STRING);
		}
	}
	return res;
}

QWORD Utils::FileSize(LPCSTR lpFilename)
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
		return false;
	}
	DWORD noBytesRead;
	::ReadFile(hFile, pvBuffer, dwSize, &noBytesRead, NULL);
	CloseHandle(hFile);
	if (noBytesRead <= 0)
		return false;
	return true;
}

BOOL Utils::WriteFile(LPCSTR lpFilename, PVOID pvBuffer, DWORD dwSize)
{
	HANDLE hFile = CreateFile(lpFilename, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		// InfoPrint("CreateFile: %04X\n", GetLastError());
		return false;
	}
	DWORD noBytesWritten;
	::WriteFile(hFile, pvBuffer, dwSize, &noBytesWritten, NULL);
	CloseHandle(hFile);
	if (noBytesWritten != dwSize)
		return false;
	return true;
}