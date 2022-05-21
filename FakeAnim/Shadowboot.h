#pragma once

#define HvxCall QWORD _declspec(naked)

#define SHADOWBOOT_SIZE 0xD0000

void CreateShadowbootThread(LPCSTR lpFilename);