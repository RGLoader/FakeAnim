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

static HvxCall HvxBlowFuses(QWORD inp1)
{
	__asm
	{
		li    r0, 0x22
		sc
		blr
	}
}

// function each thread will run (do not run on thread 0)
void Quiesce()
{
	HvxQuiesceProcessor(2); // shadowboot pause reason: 2
}

// this must be run on thread 0
void LaunchShadowboot(LPCSTR lpFilename)
{
	// load your shadowboot here
	DWORD cbBuf = FileSize(lpFilename);
	if (cbBuf == -1) {
		InfoPrint("Error getting file size!\n");
		return;
	}
	InfoPrint("Shadowboot size: 0x%X\n", cbBuf);
	/*if (cbBuf < SHADOWBOOT_SIZE) {
		InfoPrint("Adjusting shadowboot size (0x%X/0x%X)...\n", cbBuf, SHADOWBOOT_SIZE);
		cbBuf = SHADOWBOOT_SIZE;
	}*/
	PBYTE pbBuf = (PBYTE)XPhysicalAlloc(cbBuf, MAXULONG_PTR, 0x1000, PAGE_READWRITE);
	ZeroMemory(pbBuf, cbBuf);
	if (!ReadFile(lpFilename, pbBuf, cbBuf)) {
		InfoPrint("Error reading 0x%X bytes from \"%s\"!\n", cbBuf, lpFilename);
		return;
	}

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
	HvxShadowboot(MmGetPhysicalAddress(pbBuf), cbBuf, 0x200);
	XPhysicalFree(pbBuf);
	return;
}

void CreateShadowbootThread(LPCSTR lpFilename) {
	HANDLE hThread;
	DWORD hThreadId;
	ExCreateThread(&hThread, 0, &hThreadId, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)LaunchShadowboot, (LPVOID)lpFilename, 0x427);
	XSetThreadProcessor(hThread, 0); // important, make sure its on thread 0.
	SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
	ResumeThread(hThread);
}