#include "stdafx.h"

void InfoPrint(const char* data, ...) {
	va_list argp;
	char temp[512];

	DbgPrint("[FakeAnim] ");
	va_start(argp, data);
	RtlSnprintf(temp, 512, data, argp);
	va_end(argp);
	DbgPrint(temp);
}

void HexPrint(BYTE* data, size_t len) {
	for (int i = 0; i < len; i++) {
		DbgPrint("%02X", data[i]);
	}
}

HRESULT MountPath(const char* szDrive, const char* szDevice, const char* sysStr)
{
	STRING DeviceName, LinkName;
	CHAR szDestinationDrive[MAX_PATH];
	RtlSnprintf(szDestinationDrive, MAX_PATH, sysStr, szDrive);
	RtlInitAnsiString(&DeviceName, szDevice);
	RtlInitAnsiString(&LinkName, szDestinationDrive);
	ObDeleteSymbolicLink(&LinkName);
	return (HRESULT)ObCreateSymbolicLink(&LinkName, &DeviceName);
}

HRESULT CreateSymbolicLink(const char* szDrive, const char* szDevice, BOOL both) {
	HRESULT res = -1;
	if (both) {
		InfoPrint("Mounting as both!\n");
		res = MountPath(szDrive, szDevice, OBJ_SYS_STRING);
		res |= MountPath(szDrive, szDevice, OBJ_USR_STRING);
	} else {
		if (KeGetCurrentProcessType() == PROC_SYSTEM) {
			InfoPrint("Mounting as system!\n");
			res = MountPath(szDrive, szDevice, OBJ_SYS_STRING);
		} else {
			InfoPrint("Mounting as user!\n");
			res = MountPath(szDrive, szDevice, OBJ_USR_STRING);
		}
	}
	return res;
}

QWORD FileSize(LPCSTR filename)
{
	WIN32_FILE_ATTRIBUTE_DATA fad;
	if (GetFileAttributesEx(filename, GetFileExInfoStandard, &fad) == FALSE)
		return -1; // error condition, could call GetLastError to find out more
	LARGE_INTEGER size;
	size.HighPart = fad.nFileSizeHigh;
	size.LowPart = fad.nFileSizeLow;
	return size.QuadPart;
}

bool ReadFile(LPCSTR filename, PVOID buffer, DWORD size)
{
	HANDLE file = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		// InfoPrint("Couldn't open %s\n", filename);
		return false;
	}
	DWORD noBytesRead;
	::ReadFile(file, buffer, size, &noBytesRead, NULL);
	CloseHandle(file);
	if (noBytesRead <= 0)
		return false;
	return true;
}

bool WriteFile(LPCSTR filename, PVOID buffer, DWORD size)
{
	HANDLE file = CreateFile(filename, GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		// InfoPrint("Couldn't open %s\n", filename);
		return false;
	}
	DWORD noBytesWritten;
	::WriteFile(file, buffer, size, &noBytesWritten, NULL);
	CloseHandle(file);
	if (noBytesWritten != size)
		return false;
	return true;
}