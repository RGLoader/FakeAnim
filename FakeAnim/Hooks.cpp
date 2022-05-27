#include "Bootanim.h"

char m_hookSection[0x500];
int m_hookCount;

DWORD ResolveFunction(PCHAR pcMod, DWORD dwOrd)
{
	UINT32 ptr32 = 0, ret = 0, ptr2 = 0;
	ret = XexGetModuleHandle(pcMod, (PHANDLE)&ptr32); //xboxkrnl.exe xam.dll?
	if (ret == 0)
	{
		ret = XexGetProcedureAddress((HANDLE)ptr32, dwOrd, &ptr2);
		if (ptr2 != 0)
			return ptr2;
	}
	return 0; // function not found
}

VOID __declspec(naked) GLPR_FUN(VOID)
{
	__asm {
		std     r14, -0x98(sp)
		std     r15, -0x90(sp)
		std     r16, -0x88(sp)
		std     r17, -0x80(sp)
		std     r18, -0x78(sp)
		std     r19, -0x70(sp)
		std     r20, -0x68(sp)
		std     r21, -0x60(sp)
		std     r22, -0x58(sp)
		std     r23, -0x50(sp)
		std     r24, -0x48(sp)
		std     r25, -0x40(sp)
		std     r26, -0x38(sp)
		std     r27, -0x30(sp)
		std     r28, -0x28(sp)
		std     r29, -0x20(sp)
		std     r30, -0x18(sp)
		std     r31, -0x10(sp)
		stw     r12, -0x8(sp)
		blr
	}
}

DWORD InterpretBranchDestination(DWORD dwCurrAddr, DWORD dwBrInst)
{
	DWORD ret;
	int destOff = dwBrInst & 0x3FFFFFC;
	int currOff = dwCurrAddr & ~0x80000000; // make it a positive int
	if (dwBrInst & 0x2000000) // backward branch
		destOff = destOff | 0xFC000000; // sign extend
	ret = (DWORD)(currOff + destOff);
	return (ret | (dwCurrAddr & 0x80000000)); // put back the bit if it was used
}

DWORD FindInterpretBranch(PDWORD pdwStartAddr, DWORD dwMaxSearch)
{
	DWORD i;
	DWORD ret = 0;
	for (i = 0; i < dwMaxSearch; i++)
	{
		if ((pdwStartAddr[i] & 0xFC000000) == 0x48000000)
		{
			ret = InterpretBranchDestination((DWORD)&pdwStartAddr[i], pdwStartAddr[i]);
			i = dwMaxSearch;
		}
	}
	return ret;
}

DWORD RelinkGPLR(int offset, PDWORD pdwSaveStubAddr, PDWORD pdwOrgAddr)
{
	DWORD inst = 0, repl;
	int i;
	PDWORD saver = (PDWORD)GLPR_FUN;
	// if the msb is set in the instruction, set the rest of the bits to make the int negative
	if (offset & 0x2000000)
		offset = offset | 0xFC000000;
	//DbgPrint("frame save offset: %08x\n", offset);
	repl = pdwOrgAddr[offset / 4];
	//DbgPrint("replacing %08x\n", repl);
	for (i = 0; i < 20; i++)
	{
		if (repl == saver[i])
		{
			int newOffset = (int)&saver[i] - (int)pdwSaveStubAddr;
			inst = 0x48000001 | (newOffset & 0x3FFFFFC);
			//DbgPrint("saver addr: %08x savestubaddr: %08x\n", &saver[i], saveStubAddr);
		}
	}
	//DbgPrint("new instruction: %08x\n", inst);
	return inst;
}

VOID HookFunctionStart(PDWORD pdwAddr, PDWORD pdwSaveStub, DWORD dwDest)
{
	if ((pdwSaveStub != NULL) && (pdwAddr != NULL))
	{
		int i;
		DWORD addrReloc = (DWORD)(&pdwAddr[4]);// replacing 4 instructions with a jump, this is the stub return address
		//DbgPrint("hooking addr: %08x savestub: %08x dest: %08x addreloc: %08x\n", addr, saveStub, dest, addrReloc);
		// build the stub
		// make a jump to go to the original function start+4 instructions
		DWORD writeBuffer;

		writeBuffer = 0x3D600000 + (((addrReloc >> 16) & 0xFFFF) + (addrReloc & 0x8000 ? 1 : 0)); // lis %r11, dest>>16 + 1
		pdwSaveStub[0] = writeBuffer;

		writeBuffer = 0x396B0000 + (addrReloc & 0xFFFF); // addi %r11, %r11, dest&0xFFFF
		pdwSaveStub[1] = writeBuffer;

		writeBuffer = 0x7D6903A6; // mtctr %r11
		pdwSaveStub[2] = writeBuffer;

		// instructions [3] through [6] are replaced with the original instructions from the function hook
		// copy original instructions over, relink stack frame saves to local ones
		for (i = 0; i < 4; i++)
		{
			writeBuffer = ((pdwAddr[i] & 0x48000003) == 0x48000001) ? RelinkGPLR((pdwAddr[i] & ~0x48000003), &pdwSaveStub[i + 3], &pdwAddr[i]) : pdwAddr[i];
			pdwSaveStub[i + 3] = writeBuffer;
		}
		writeBuffer = 0x4E800420; // bctr
		pdwSaveStub[7] = writeBuffer;

		doSync(pdwSaveStub);

		//DbgPrint("savestub:\n");
		//for(i = 0; i < 8; i++)
		//{
		//	DbgPrint("PatchDword(0x%08x, 0x%08x);\n", &saveStub[i], saveStub[i]);
		//}
		// patch the actual function to jump to our replaced one
		PatchInJump(pdwAddr, dwDest, FALSE);
	}
}

VOID UnhookFunctionStart(PDWORD pdwAddr, PDWORD pdwOldData)
{
	if ((pdwAddr != NULL) && (pdwOldData != NULL))
	{
		int i;
		for (i = 0; i < 4; i++)
		{
			pdwAddr[i] = pdwOldData[i];
		}
		doSync(pdwAddr);
	}
}

DWORD HookFunctionStub(PDWORD pdwAddr, PVOID vpFunc) {
	DWORD* startStub = (DWORD*)&m_hookSection[m_hookCount * 32];
	m_hookCount++;

	for (auto i = 0; i < 7; i++)
		startStub[i] = 0x60000000;
	startStub[7] = 0x4E800020;

	HookFunctionStart(pdwAddr, startStub, (DWORD)vpFunc);
	return (DWORD)startStub;
}

DWORD FindInterpretBranchOrdinal(PCHAR pcMod, DWORD dwOrd, DWORD dwMaxSearch)
{
	DWORD ret = 0;
	PDWORD search = (PDWORD)ResolveFunction(pcMod, dwOrd);
	if (search != NULL)
		ret = FindInterpretBranch(search, dwMaxSearch);
	return ret;
}

VOID PatchInJump(PDWORD pdwAddr, DWORD dwDest, BOOL bLinked)
{
	DWORD writeBuffer;

	writeBuffer = 0x3D600000 + (((dwDest >> 16) & 0xFFFF) + (dwDest & 0x8000 ? 1 : 0)); // lis %r11, dest>>16 + 1
	pdwAddr[0] = writeBuffer;

	writeBuffer = 0x396B0000 + (dwDest & 0xFFFF); // addi %r11, %r11, dest&0xFFFF
	pdwAddr[1] = writeBuffer;

	writeBuffer = 0x7D6903A6; // mtctr %r11
	pdwAddr[2] = writeBuffer;

	writeBuffer = 0x4E800420 | (bLinked ? 1 : 0); // bctr
	pdwAddr[3] = writeBuffer;

	doSync(pdwAddr);
}

////////////////////////////////////////////////////////////////////////
// This is the modified version of hookImpStub
// modified to work with Devkits

BOOL HookImpStubDebug(PCHAR pcMod, PCHAR pcImpMod, DWORD dwOrd, DWORD dwPatchAddr)
{
	DWORD orgAddr;
	PLDR_DATA_TABLE_ENTRY ldat;
	int i, j;
	BOOL ret = FALSE;
	// get the address of the actual function that is jumped to
	orgAddr = ResolveFunction(pcImpMod, dwOrd);
	if (orgAddr != 0)
	{
		// find where kmod info is stowed
		ldat = (PLDR_DATA_TABLE_ENTRY)GetModuleHandle(pcMod);
		if (ldat != NULL)
		{
			// use kmod info to find xex header in memory
			PXEX_IMPORT_DESCRIPTOR imps = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(ldat->XexHeaderBase, 0x000103FF);
			if (imps != NULL)
			{
				char* impName = (char*)(imps + 1);
				PXEX_IMPORT_TABLE impTbl = (PXEX_IMPORT_TABLE)(impName + imps->NameTableSize);
				for (i = 0; i < (int)(imps->ModuleCount); i++)
				{
					// use import descriptor strings to refine table
					for (j = 0; j < impTbl->ImportCount; j++)
					{
						PDWORD add = (PDWORD)impTbl->ImportStubAddr[j];
						if (add[0] == orgAddr)
						{
							HRESULT hr;
							hr = (HRESULT)CopyMemory(add, (LPCVOID)dwPatchAddr, 4);
							//DbgPrint("XTW: 2 hr = 0x%008X | at addr: 0x%08X\n", hr, add);
							BYTE data[0x10];
							PatchInJump((PDWORD)data, dwPatchAddr, FALSE);
							hr = (HRESULT)CopyMemory((PDWORD)(impTbl->ImportStubAddr[j + 1]), (LPCVOID)data, 0x10);
							//memcpy((PDWORD)(impTbl->ImportStubAddr[j+1]), data, 0x10);
							//DbgPrint("XTW: 2 hr = 0x%008X | at addr: 0x%08X\n", hr, (PDWORD)(impTbl->ImportStubAddr[j+1]));
							//DbgPrint("%s %s tbl %d has ord %x at tstub %d location %08x\n", modname, impName, i, ord, j, impTbl->ImportStubAddr[j+1]);
							//patchInJump((PDWORD)(impTbl->ImportStubAddr[j+1]), patchAddr, FALSE);
							j = impTbl->ImportCount;
							ret = TRUE;
						}
					}
					impTbl = (PXEX_IMPORT_TABLE)((BYTE*)impTbl + impTbl->TableSize);
					impName = impName + Utils::StringLength(impName);
					while ((impName[0] & 0xFF) == 0x0)
						impName++;
				}
			}
			//else DbgPrint("could not find import descriptor for mod %s\n", modname);
		}
		//else DbgPrint("could not find data table for mod %s\n", modname);
	}
	//else DbgPrint("could not find ordinal %d in mod %s\n", ord, impmodname);

	return ret;
}

DWORD MakeBranch(DWORD dwBranchAddr, DWORD dwDest, BOOL bLinked) {
	return (0x48000000) | ((dwDest - dwBranchAddr) & 0x03FFFFFF) | (DWORD)bLinked;
}