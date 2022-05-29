#include "Bootanim.h"

// function each thread will run (do not run on thread 0)
void Quiesce()
{
	HvxQuiesceProcessor(2); // shadowboot pause reason: 2
}

DWORD rc_crc32(DWORD dwCrc, const PBYTE pbData, DWORD dwSize) {
	static DWORD table[256];
	static int have_table = 0;
	DWORD rem;
	BYTE octet;
	int i, j;
	PBYTE p;
	PBYTE q;

	/* This check is not thread safe; there is no mutex. */
	if (have_table == 0) {
		/* Calculate CRC table. */
		for (i = 0; i < 256; i++) {
			rem = i;  /* remainder from polynomial division */
			for (j = 0; j < 8; j++) {
				if (rem & 1) {
					rem >>= 1;
					rem ^= 0xEDB88320;
				}
				else
					rem >>= 1;
			}
			table[i] = rem;
		}
		have_table = 1;
	}

	dwCrc = ~dwCrc;
	q = pbData + dwSize;
	for (p = pbData; p < q; p++) {
		octet = *p;  /* Cast to unsigned octet. */
		dwCrc = (dwCrc >> 8) ^ table[(dwCrc & 0xFF) ^ octet];
	}
	return ~dwCrc;
}

Shadowboot::PATCH_SHADOWBOOT_STATUS PatchShadowboot(PBYTE pbData, DWORD dwSize) {
	BYTE bNullKey[0x10];
	ZeroMemory(bNullKey, sizeof(bNullKey));

	XECRYPT_RSAPUB_2048 _1BlPubKey;
	HvPeekBytes(0x8000020000005730, &_1BlPubKey, sizeof(XECRYPT_RSAPUB_2048));

	BYTE b1BlSalt[0xA];
	ZeroMemory(b1BlSalt, sizeof(b1BlSalt));
	HvPeekBytes(0x8000020000005888, b1BlSalt, sizeof(b1BlSalt));

	// flash header
	PBLDR_FLASH pFlashHdr = (PBLDR_FLASH)pbData;
#pragma region SB
	// SB header
	PBLDR_HEADER pSbBldrHdr = (PBLDR_HEADER)(pbData + pFlashHdr->blHeader.Entry);
	if (pSbBldrHdr->Magic != 0x5342) {
		DbgPrint("INVALID_SB_HEADER");
		return Shadowboot::PATCH_SHADOWBOOT_STATUS::INVALID_SB_HEADER;
	}
	if (pSbBldrHdr->Build != 14352) {
		DbgPrint("INVALID_SB_VERSION");
		return Shadowboot::PATCH_SHADOWBOOT_STATUS::INVALID_SB_VERSION;
	}
	PBYTE pbSbNonce = (PBYTE)pSbBldrHdr + sizeof(BLDR_HEADER);
	PBYTE pbSbData = pbSbNonce + FLASH_NONCE_SIZE;
	BYTE bSbKey[0x10];
	XeCryptHmacSha((PBYTE)_1BL_KEY, sizeof(_1BL_KEY), pbSbNonce, FLASH_NONCE_SIZE, NULL, 0, NULL, 0, bSbKey, 0x10);
	ZeroMemory(pbSbNonce, FLASH_NONCE_SIZE);
	XeCryptRc4(bSbKey, sizeof(bSbKey), pbSbData, pSbBldrHdr->Size - (sizeof(BLDR_HEADER) + FLASH_NONCE_SIZE));

	BYTE bSbHash[XECRYPT_SHA_DIGEST_SIZE];
	ZeroMemory(bSbHash, XECRYPT_SHA_DIGEST_SIZE);
	XeCryptRotSumSha((PBYTE)pSbBldrHdr, 0x10, (PBYTE)pSbBldrHdr + 0x140, pSbBldrHdr->Size - 0x140, bSbHash, XECRYPT_SHA_DIGEST_SIZE);
	if (!XeCryptBnQwBeSigVerify((PXECRYPT_SIG)pbSbData + 0x20, bSbHash, b1BlSalt, (PXECRYPT_RSA)&_1BlPubKey)) {
		DbgPrint("INVALID_SB_SIGNATURE\n");
		return Shadowboot::PATCH_SHADOWBOOT_STATUS::INVALID_SB_SIGNATURE;
	}
#pragma endregion SB
#pragma region SC
	// SC header
	PBLDR_HEADER pScBldrHdr = (PBLDR_HEADER)((PBYTE)pSbBldrHdr + pSbBldrHdr->Size);
	if (pScBldrHdr->Magic != 0x5343) {
		DbgPrint("INVALID_SC_HEADER\n");
		return Shadowboot::PATCH_SHADOWBOOT_STATUS::INVALID_SC_HEADER;
	}
	if (pScBldrHdr->Build != 17489) {
		DbgPrint("INVALID_SC_VERSION\n");
		return Shadowboot::PATCH_SHADOWBOOT_STATUS::INVALID_SC_VERSION;
	}

	PBYTE pbScNonce = (PBYTE)pScBldrHdr + sizeof(BLDR_HEADER);
	PBYTE pbScData = pbScNonce + FLASH_NONCE_SIZE;
	BYTE bScKey[0x10];
	XeCryptHmacSha(bNullKey, sizeof(bNullKey), pbScNonce, FLASH_NONCE_SIZE, NULL, 0, NULL, 0, bScKey, 0x10);
	ZeroMemory(pbScNonce, FLASH_NONCE_SIZE);
	XeCryptRc4(bScKey, sizeof(bScKey), pbScData, pScBldrHdr->Size - (sizeof(BLDR_HEADER) + FLASH_NONCE_SIZE));

	BYTE bScHash[XECRYPT_SHA_DIGEST_SIZE];
	ZeroMemory(bScHash, XECRYPT_SHA_DIGEST_SIZE);
	XeCryptRotSumSha((PBYTE)pScBldrHdr, 0x10, (PBYTE)pScBldrHdr + 0x120, pScBldrHdr->Size - 0x120, bScHash, XECRYPT_SHA_DIGEST_SIZE);
	if (!XeCryptBnQwBeSigVerify((PXECRYPT_SIG)pbScData, bScHash, (PBYTE)pSbBldrHdr + 904, (PXECRYPT_RSA)((PBYTE)pSbBldrHdr + 616))) {
		DbgPrint("INVALID_SC_SIGNATURE\n");
		return Shadowboot::PATCH_SHADOWBOOT_STATUS::INVALID_SC_SIGNATURE;
	}
#pragma endregion SC
#pragma region SD
	// SD header
	PBLDR_HEADER pSdBldrHdr = (PBLDR_HEADER)((PBYTE)pScBldrHdr + pScBldrHdr->Size);
	if (pSdBldrHdr->Magic != 0x5344) {
		DbgPrint("INVALID_SD_HEADER\n");
		return Shadowboot::PATCH_SHADOWBOOT_STATUS::INVALID_SD_HEADER;
	}
	if (pSdBldrHdr->Build != 17489) {
		DbgPrint("INVALID_SD_VERSION\n");
		return Shadowboot::PATCH_SHADOWBOOT_STATUS::INVALID_SD_VERSION;
	}
	// SD nonce
	PBYTE pbSdNonce = (PBYTE)pSdBldrHdr + sizeof(BLDR_HEADER);
	// SD data
	PBYTE pbSdData = pbSdNonce + FLASH_NONCE_SIZE;
	BYTE bSdKey[0x10];
	XeCryptHmacSha(bScKey, sizeof(bScKey), pbSdNonce, FLASH_NONCE_SIZE, NULL, 0, NULL, 0, bSdKey, 0x10);
	ZeroMemory(pbSdNonce, FLASH_NONCE_SIZE);
	XeCryptRc4(bSdKey, sizeof(bSdKey), pbSdData, pSdBldrHdr->Size - (sizeof(BLDR_HEADER) + FLASH_NONCE_SIZE));

	BYTE bSdHash[XECRYPT_SHA_DIGEST_SIZE];
	ZeroMemory(bSdHash, XECRYPT_SHA_DIGEST_SIZE);
	XeCryptRotSumSha((PBYTE)pSdBldrHdr, 0x10, (PBYTE)pSdBldrHdr + 0x120, pSdBldrHdr->Size - 0x120, bSdHash, XECRYPT_SHA_DIGEST_SIZE);
	if (!XeCryptBnQwBeSigVerify((PXECRYPT_SIG)pbSdData, bSdHash, (PBYTE)pSbBldrHdr + 914, (PXECRYPT_RSA)((PBYTE)pSbBldrHdr + 616))) {
		DbgPrint("INVALID_SD_SIGNATURE\n");
		return Shadowboot::PATCH_SHADOWBOOT_STATUS::INVALID_SD_SIGNATURE;
	}
#pragma endregion SD
#pragma region SE
	PBLDR_HEADER pSeBldrHdr = (PBLDR_HEADER)((PBYTE)pSdBldrHdr + pSdBldrHdr->Size);
	if (pSeBldrHdr->Magic != 0x5345) {
		DbgPrint("INVALID_SE_HEADER\n");
		return Shadowboot::PATCH_SHADOWBOOT_STATUS::INVALID_SE_HEADER;
	}
	if (pSeBldrHdr->Build != 17489) {
		DbgPrint("INVALID_SE_VERSION\n");
		return Shadowboot::PATCH_SHADOWBOOT_STATUS::INVALID_SE_VERSION;
	}
	// correct SE size for decryption and hashing
	DWORD dwSePaddedSize = pSeBldrHdr->Size + 0xF & 0xFFFFFFF0;
	// SE nonce
	PBYTE pbSeNonce = (PBYTE)pSeBldrHdr + sizeof(BLDR_HEADER);
	// SE data
	PBYTE pbSeData = pbSeNonce + FLASH_NONCE_SIZE;
	BYTE bSeKey[0x10];
	XeCryptHmacSha(bSdKey, sizeof(bSdKey), pbSeNonce, FLASH_NONCE_SIZE, NULL, 0, NULL, 0, bSeKey, 0x10);
	ZeroMemory(pbSeNonce, FLASH_NONCE_SIZE);
	XeCryptRc4(bSeKey, sizeof(bSeKey), pbSeData, dwSePaddedSize - (sizeof(BLDR_HEADER) + FLASH_NONCE_SIZE));
	
	BYTE bSeHash[XECRYPT_SHA_DIGEST_SIZE];
	ZeroMemory(bSeHash, XECRYPT_SHA_DIGEST_SIZE);
	XeCryptRotSumSha((PBYTE)pSeBldrHdr, 0x10, pbSeData, dwSePaddedSize - 0x20, bSeHash, XECRYPT_SHA_DIGEST_SIZE);
	if (!RtlEqualMemory(bSeHash, (PBYTE)pSdBldrHdr + 588, XECRYPT_SHA_DIGEST_SIZE)) {
		DbgPrint("INVALID_SE_DIGEST\n");
		return Shadowboot::PATCH_SHADOWBOOT_STATUS::INVALID_SE_DIGEST;
	}
#pragma endregion SE
#pragma region Checksums
	if (rc_crc32(0xFFFFFFFF, (PBYTE)pSbBldrHdr, pSbBldrHdr->Size) != 0x2EA6BDFB) {
		DbgPrint("INVALID_SB_CHECKSUM\n");
		return Shadowboot::PATCH_SHADOWBOOT_STATUS::INVALID_SB_CHECKSUM;
	}
	// no checksum on SC since it can vary so much
	if (rc_crc32(0xFFFFFFFF, (PBYTE)pSdBldrHdr, pSdBldrHdr->Size) != 0xBA7A0F91) {
		DbgPrint("INVALID_SD_CHECKSUM\n");
		return Shadowboot::PATCH_SHADOWBOOT_STATUS::INVALID_SD_CHECKSUM;
	}
	if (rc_crc32(0xFFFFFFFF, (PBYTE)pSeBldrHdr, dwSePaddedSize) != 0xF7B5ABD3) {
		DbgPrint("INVALID_SE_CHECKSUM\n");
		return Shadowboot::PATCH_SHADOWBOOT_STATUS::INVALID_SE_CHECKSUM;
	}

	DbgPrint("SB: 0x%04X\n", rc_crc32(0xFFFFFFFF, (PBYTE)pSbBldrHdr, pSbBldrHdr->Size));
	DbgPrint("SC: 0x%04X\n", rc_crc32(0xFFFFFFFF, (PBYTE)pScBldrHdr, pScBldrHdr->Size));
	DbgPrint("SD: 0x%04X\n", rc_crc32(0xFFFFFFFF, (PBYTE)pSdBldrHdr, pSdBldrHdr->Size));
	DbgPrint("SE: 0x%04X\n", rc_crc32(0xFFFFFFFF, (PBYTE)pSeBldrHdr, dwSePaddedSize));
#pragma endregion Checksums
#pragma region Patches
	// patch SB flag checks, these break the SB signature but we've patched the check in the HV already
	BYTE bPatch0[4] = { 0x48, 0x00, 0x01, 0x94 };
	CopyMemory((PBYTE)pSbBldrHdr + 0x1348, bPatch0, sizeof(bPatch0));
	BYTE bPatch1[4] = { 0x4E, 0x80, 0x00, 0x20 };
	CopyMemory((PBYTE)pSbBldrHdr + 0x1E10, bPatch1, sizeof(bPatch1));
#pragma endregion Patches
#pragma region Repack
	// generate nonces
	XeCryptRandom(pbSbNonce, FLASH_NONCE_SIZE);
	XeCryptRandom(pbScNonce, FLASH_NONCE_SIZE);
	XeCryptRandom(pbSdNonce, FLASH_NONCE_SIZE);
	XeCryptRandom(pbSeNonce, FLASH_NONCE_SIZE);
	// generate keys
	XeCryptHmacSha((PBYTE)_1BL_KEY, sizeof(_1BL_KEY), pbSbNonce, FLASH_NONCE_SIZE, NULL, 0, NULL, 0, bSbKey, 0x10);
	XeCryptHmacSha(bNullKey, sizeof(bNullKey), pbScNonce, FLASH_NONCE_SIZE, NULL, 0, NULL, 0, bScKey, 0x10);
	XeCryptHmacSha(bScKey, sizeof(bScKey), pbSdNonce, FLASH_NONCE_SIZE, NULL, 0, NULL, 0, bSdKey, 0x10);
	XeCryptHmacSha(bSdKey, sizeof(bSdKey), pbSeNonce, FLASH_NONCE_SIZE, NULL, 0, NULL, 0, bSeKey, 0x10);
	// encrypt bootloaders
	XeCryptRc4(bSbKey, sizeof(bSbKey), pbSbData, pSbBldrHdr->Size - (sizeof(BLDR_HEADER) + FLASH_NONCE_SIZE));
	XeCryptRc4(bScKey, sizeof(bScKey), pbScData, pScBldrHdr->Size - (sizeof(BLDR_HEADER) + FLASH_NONCE_SIZE));
	XeCryptRc4(bSdKey, sizeof(bSdKey), pbSdData, pSdBldrHdr->Size - (sizeof(BLDR_HEADER) + FLASH_NONCE_SIZE));
	XeCryptRc4(bSeKey, sizeof(bSeKey), pbSeData, dwSePaddedSize - (sizeof(BLDR_HEADER) + FLASH_NONCE_SIZE));
#pragma endregion Repack

	return Shadowboot::PATCH_SHADOWBOOT_STATUS::SUCCESS;
}

//typedef PVOID MmAllocatePhysicalMemoryExProto(DWORD dwFlags, DWORD dwSize, DWORD dwProtect, DWORD dwMinAddr, DWORD dwMaxAddr, DWORD dwAlign);
//MmAllocatePhysicalMemoryExProto* MmAllocatePhysicalMemoryEx = (MmAllocatePhysicalMemoryExProto*)0x80095FD8;

typedef void KiShadowBootProto(DWORD dwAddr, DWORD dwSize, DWORD dwFlags);
KiShadowBootProto* KiShadowBoot = (KiShadowBootProto*)0x80085FA8;

//typedef DWORD ExpTryToBootMediaKernelProto(PSTRING psFilePath, BOOL bUnk1, BOOL bUnk2);
//ExpTryToBootMediaKernelProto* ExpTryToBootMediaKernel = (ExpTryToBootMediaKernelProto*)0x80070F70;

//typedef void ExpTryToShadowBootProto(void);
//ExpTryToShadowBootProto* ExpTryToShadowBoot = (ExpTryToShadowBootProto*)0x800710E0;