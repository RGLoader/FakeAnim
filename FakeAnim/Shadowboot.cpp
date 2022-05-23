#include "stdafx.h"

static HvxCall HvxQuiesceProcessor(BYTE Reason)
{
	__asm
	{
		li    r0, 0x2
		sc
		blr
	}
}

static HvxCall HvxShadowboot(PVOID pvSB, DWORD cbSB, WORD Flags)
{
	__asm
	{
		li    r0, 0x21
		sc
		blr
	}
}

// function each thread will run (do not run on thread 0)
void Quiesce()
{
	HvxQuiesceProcessor(2); // shadowboot pause reason: 2
}

PATCH_SHADOWBOOT_STATUS PatchShadowboot(PBYTE pbData, DWORD dwSize) {
	BYTE bNullKey[0x10];
	ZeroMemory(bNullKey, 0x10);

	// flash header
	PBLDR_FLASH pFlashHdr = (PBLDR_FLASH)pbData;
#pragma region SB
	// SB header
	PBLDR_HEADER pSbBldrHdr = (PBLDR_HEADER)(pbData + pFlashHdr->blHeader.Entry);
	if (pSbBldrHdr->Magic != 0x5342) {
		Utils::InfoPrint("INVALID_SB_HEADER");
		return INVALID_SB_HEADER;
	}
	if (pSbBldrHdr->Build != 14352) {
		Utils::InfoPrint("INVALID_SB_VERSION");
		return INVALID_SB_VERSION;
	}
	PBYTE pbSbNonce = (PBYTE)pSbBldrHdr + sizeof(BLDR_HEADER);
	PBYTE pbSbData = pbSbNonce + 0x10;
	BYTE bSbKey[0x10];
	XeCryptHmacSha((PBYTE)_1BL_KEY, sizeof(_1BL_KEY), pbSbNonce, 0x10, NULL, 0, NULL, 0, bSbKey, 0x10);
	ZeroMemory(pbSbNonce, 0x10);
	XeCryptRc4(bSbKey, sizeof(bSbKey), pbSbData, pSbBldrHdr->Size - (sizeof(BLDR_HEADER) + 0x10));
#pragma endregion SB
#pragma region SC
	// SC header
	PBLDR_HEADER pScBldrHdr = (PBLDR_HEADER)((PBYTE)pSbBldrHdr + pSbBldrHdr->Size);
	if (pScBldrHdr->Magic != 0x5343) {
		Utils::InfoPrint("INVALID_SC_HEADER\n");
		return INVALID_SC_HEADER;
	}
	if (pScBldrHdr->Build != 17489) {
		Utils::InfoPrint("INVALID_SC_VERSION\n");
		return INVALID_SC_VERSION;
	}

	PBYTE pbScNonce = (PBYTE)pScBldrHdr + sizeof(BLDR_HEADER);
	PBYTE pbScData = pbScNonce + 0x10;
	BYTE bScKey[0x10];
	XeCryptHmacSha(bNullKey, sizeof(bNullKey), pbScNonce, 0x10, NULL, 0, NULL, 0, bScKey, 0x10);
	ZeroMemory(pbScNonce, 0x10);
	XeCryptRc4(bScKey, sizeof(bScKey), pbScData, pScBldrHdr->Size - (sizeof(BLDR_HEADER) + 0x10));

	BYTE bScHash[XECRYPT_SHA_DIGEST_SIZE];
	ZeroMemory(bScHash, XECRYPT_SHA_DIGEST_SIZE);
	XeCryptRotSumSha((PBYTE)pScBldrHdr, 0x10, (PBYTE)pScBldrHdr + 0x120, pScBldrHdr->Size - 0x120, bScHash, XECRYPT_SHA_DIGEST_SIZE);
	if (!XeCryptBnQwBeSigVerify((PXECRYPT_SIG)pbScData, bScHash, (PBYTE)pSbBldrHdr + 904, (PXECRYPT_RSA)((PBYTE)pSbBldrHdr + 616))) {
		Utils::InfoPrint("INVALID_SC_SIGNATURE\n");
		return INVALID_SC_SIGNATURE;
	}
#pragma endregion SC
#pragma region SD
	// SD header
	PBLDR_HEADER pSdBldrHdr = (PBLDR_HEADER)((PBYTE)pScBldrHdr + pScBldrHdr->Size);
	if (pSdBldrHdr->Magic != 0x5344) {
		Utils::InfoPrint("INVALID_SD_HEADER\n");
		return INVALID_SD_HEADER;
	}
	if (pSdBldrHdr->Build != 17489) {
		Utils::InfoPrint("INVALID_SD_VERSION\n");
		return INVALID_SD_VERSION;
	}
	// SD nonce
	PBYTE pbSdNonce = (PBYTE)pSdBldrHdr + sizeof(BLDR_HEADER);
	// SD data
	PBYTE pbSdData = pbSdNonce + 0x10;
	BYTE bSdKey[0x10];
	XeCryptHmacSha(bScKey, sizeof(bScKey), pbSdNonce, 0x10, NULL, 0, NULL, 0, bSdKey, 0x10);
	ZeroMemory(pbSdNonce, 0x10);
	XeCryptRc4(bSdKey, sizeof(bSdKey), pbSdData, pSdBldrHdr->Size - (sizeof(BLDR_HEADER) + 0x10));

	BYTE bSdHash[XECRYPT_SHA_DIGEST_SIZE];
	ZeroMemory(bSdHash, XECRYPT_SHA_DIGEST_SIZE);
	XeCryptRotSumSha((PBYTE)pSdBldrHdr, 0x10, (PBYTE)pSdBldrHdr + 0x120, pSdBldrHdr->Size - 0x120, bSdHash, XECRYPT_SHA_DIGEST_SIZE);
	if (!XeCryptBnQwBeSigVerify((PXECRYPT_SIG)pbSdData, bSdHash, (PBYTE)pSbBldrHdr + 914, (PXECRYPT_RSA)((PBYTE)pSbBldrHdr + 616))) {
		Utils::InfoPrint("INVALID_SD_SIGNATURE\n");
		return INVALID_SD_SIGNATURE;
	}
#pragma endregion SD
#pragma region SE
	PBLDR_HEADER pSeBldrHdr = (PBLDR_HEADER)((PBYTE)pSdBldrHdr + pSdBldrHdr->Size);
	if (pSeBldrHdr->Magic != 0x5345) {
		Utils::InfoPrint("INVALID_SE_HEADER\n");
		return INVALID_SE_HEADER;
	}
	if (pSeBldrHdr->Build != 17489) {
		Utils::InfoPrint("INVALID_SE_VERSION\n");
		return INVALID_SE_VERSION;
	}
	// correct SE size for decryption and hashing
	DWORD dwSeSize = pSeBldrHdr->Size + 0xF & 0xFFFFFFF0;
	// SE nonce
	PBYTE pbSeNonce = (PBYTE)pSeBldrHdr + sizeof(BLDR_HEADER);
	// SE data
	PBYTE pbSeData = pbSeNonce + 0x10;
	BYTE bSeKey[0x10];
	XeCryptHmacSha(bSdKey, sizeof(bSdKey), pbSeNonce, 0x10, NULL, 0, NULL, 0, bSeKey, 0x10);
	ZeroMemory(pbSeNonce, 0x10);
	XeCryptRc4(bSeKey, sizeof(bSeKey), pbSeData, dwSeSize - (sizeof(BLDR_HEADER) + 0x10));
	
	BYTE bSeHash[XECRYPT_SHA_DIGEST_SIZE];
	ZeroMemory(bSeHash, XECRYPT_SHA_DIGEST_SIZE);
	XeCryptRotSumSha((PBYTE)pSeBldrHdr, 0x10, pbSeData, dwSeSize - 0x20, bSeHash, XECRYPT_SHA_DIGEST_SIZE);
	if (memcmp(bSeHash, (PBYTE)pSdBldrHdr + 588, XECRYPT_SHA_DIGEST_SIZE)) {
		Utils::InfoPrint("INVALID_SE_DIGEST\n");
		return INVALID_SE_DIGEST;
	}
#pragma endregion SE

	return SUCCESS;
}

// this must be run on thread 0
void LaunchShadowboot(PLAUNCH_SHADOWBOOT_ARGS pLsa)
{
	// lets make a thread to pause each processor
	HANDLE	hThread5;
	DWORD hThreadId5;
	HANDLE	hThread4;
	DWORD hThreadId4;
	HANDLE	hThread3;
	DWORD hThreadId3;
	HANDLE	hThread2;
	DWORD hThreadId2;
	HANDLE	hThread1;
	DWORD hThreadId1;
	ExCreateThread(&hThread5, 0, &hThreadId5, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)Quiesce, NULL, 0x427);
	ExCreateThread(&hThread4, 0, &hThreadId4, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)Quiesce, NULL, 0x427);
	ExCreateThread(&hThread3, 0, &hThreadId3, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)Quiesce, NULL, 0x427);
	ExCreateThread(&hThread2, 0, &hThreadId2, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)Quiesce, NULL, 0x427);
	ExCreateThread(&hThread1, 0, &hThreadId1, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)Quiesce, NULL, 0x427);

	// make sure theyre on the correct processor
	XSetThreadProcessor(hThread5, 5);
	XSetThreadProcessor(hThread4, 4);
	XSetThreadProcessor(hThread3, 3);
	XSetThreadProcessor(hThread2, 2);
	XSetThreadProcessor(hThread1, 1);

	// make sure the kernel can't inturrupt our threads and corrupt the system
	SetThreadPriority(hThread5, THREAD_PRIORITY_TIME_CRITICAL);
	SetThreadPriority(hThread4, THREAD_PRIORITY_TIME_CRITICAL);
	SetThreadPriority(hThread3, THREAD_PRIORITY_TIME_CRITICAL);
	SetThreadPriority(hThread2, THREAD_PRIORITY_TIME_CRITICAL);
	SetThreadPriority(hThread1, THREAD_PRIORITY_TIME_CRITICAL);

	// proceed with pausing the processors
	ResumeThread(hThread5);
	ResumeThread(hThread4);
	ResumeThread(hThread3);
	ResumeThread(hThread2);
	ResumeThread(hThread1);

	// call HvxShadowboot here
	HvxShadowboot(MmGetPhysicalAddress(pLsa->pbData), pLsa->dwSize, 0x200);
	XPhysicalFree(pLsa->pbData);

	return;
}

void CreateShadowbootThread(LPCSTR lpFilename) {
	// load your shadowboot here
	QWORD qwSize = Utils::FileSize(lpFilename);
	if (qwSize == -1) {
		Utils::InfoPrint("Error getting file size!\n");
		return;
	}
	PBYTE pbData = (PBYTE)XPhysicalAlloc(qwSize, MAXULONG_PTR, 0x1000, PAGE_READWRITE);
	ZeroMemory(pbData, qwSize);
	if (!Utils::ReadFile(lpFilename, pbData, qwSize)) {
		Utils::InfoPrint("Error reading 0x%08X bytes from \"%s\"!\n", qwSize, lpFilename);
		return;
	}

	// PatchShadowboot(pbData, qwSize);

#ifndef DEVKIT_TEST
	HANDLE hThread;
	DWORD hThreadId;
	LAUNCH_SHADOWBOOT_ARGS lsa = { 0 };
	lsa.pbData = pbData;
	lsa.dwSize = qwSize;
	ExCreateThread(&hThread, 0, &hThreadId, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)LaunchShadowboot, (LPVOID)&lsa, 0x427);
	XSetThreadProcessor(hThread, 0); // important, make sure its on thread 0.
	SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
	ResumeThread(hThread);
#else
	XPhysicalFree(pbData);
#endif
}