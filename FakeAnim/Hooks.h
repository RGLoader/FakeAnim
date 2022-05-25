#pragma once

VOID PatchInJump(PDWORD pdwAddr, DWORD dwDest, BOOL bLinked);
DWORD HookFunctionStub(PDWORD pdwAddr, PVOID vpFunc);