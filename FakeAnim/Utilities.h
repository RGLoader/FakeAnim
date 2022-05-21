#pragma once

void InfoPrint(const char* data, ...);
void HexPrint(BYTE* data, size_t len);
HRESULT CreateSymbolicLink(const char* szDrive, const char* szDevice, BOOL both);
BOOL ApplyHVPatches(BYTE* patches, size_t size);
QWORD FileSize(LPCSTR filename);
bool ReadFile(LPCSTR filename, PVOID buffer, DWORD size);
bool WriteFile(LPCSTR filename, PVOID buffer, DWORD size);