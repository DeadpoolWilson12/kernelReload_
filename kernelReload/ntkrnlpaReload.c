/*
	踩坑:不能直接修复重定位表为新内核偏移，重定位表要先修为老内核偏移，再把SSDT里面函数地址修正为新内核的
	原因:我们只用新内核的函数，全局变量还是用老内核的 
*/

#include "ntkrnlpaReload.h"

DWORD								FileSize = 0;
PVOID								pFileBuffer = NULL;
DWORD                               OrignImage = 0;
PKSERVICE_TABLE_DESCRIPTOR          pNewKeServiceDescriptorTable = NULL;
PVOID								pImageBuffer = NULL;

PVOID                               pNewImageBase = NULL;
PORIGINALCOMD						pOrigianlCmd = NULL;
CHAR								OriginalCode[64] = "\x2b\xe1\xc1\xe9\x02";
CHAR                                NewCode[64];
ULONG								BackAddr = 0;

PIMAGE_DOS_HEADER					pDosHeader = NULL;
PIMAGE_NT_HEADERS					pNTHeader = NULL;
PIMAGE_FILE_HEADER					pFileHeader = NULL;
PIMAGE_OPTIONAL_HEADER32			pOptionalHeader = NULL;
PIMAGE_SECTION_HEADER				pSectionHeader = NULL;
PIMAGE_BASE_RELOCATION				pReloactionDirectory = NULL;
PIMAGE_THUNK_DATA					pIATDirectory = NULL;

void __declspec(naked) HookProc()
{
	// eax里存的是编号，ebx是函数的地址，edi里是地址表的指针
	// 不可以在这个函数里读寄存器,不知道为啥
	__asm
	{
		pushad
		pushfd
		push ebx
		push eax
		push edi
		call SSDTfilter
		mov [esp + 0x14],eax
	}

	// DbgPrint("Hook Success!\n");

	__asm
	{
		popfd
		popad
		jmp [pOrigianlCmd]
		/*sub  esp, ecx
		shr  ecx, 2
		jmp  BackAddr*/

	}
}

DWORD32 SSDTfilter(DWORD ServiceTableBase_, DWORD FuncIndex_, DWORD32 OrigFuncAddress_)
{
	if (ServiceTableBase_ == (DWORD32)KeServiceDescriptorTable->ntoskrnl.ServiceTableBase)
	{
		// if(!strcmp((char*)PsGetCurrentProcess() + 0x174, PROTECTPROCESS) && FuncIndex_ == 122) // 186是NtReadVirtualMemory; 122是NtOpenProcess
		if (FuncIndex_ == 122)
		{
			DWORD32 FuncAddr = pNewKeServiceDescriptorTable->ntoskrnl.ServiceTableBase[FuncIndex_];
			DbgPrint("Success Use My Kernel, FuncIndex_:0x%x, FuncAddr:%x\n", FuncIndex_, FuncAddr);
			return FuncAddr;
		}
	}
	return OrigFuncAddress_;
}

VOID PageProtectOn()
{
	__asm
	{
		mov eax, cr0
		and eax, not 10000h
		mov cr0, eax
		sti // 开启中断
	}
}

VOID PageProtectOff()
{
	__asm
	{
		cli // 屏蔽所有中断
		mov eax, cr0
		or eax, 10000h
		mov cr0, eax
	}
}

DWORD Align(int x, DWORD Alignment)
{
	if (x % Alignment == 0)
	{
		return x;
	}
	else
	{
		return (1 + (x / Alignment)) * Alignment;
	}
}

DWORD RVA_TO_FOA(DWORD dwRva)
{
	DWORD dwFov = 0;

	if (dwRva < pOptionalHeader->SizeOfHeaders && dwRva != 0)
	{
		dwFov = dwRva;
		return dwFov;
	}

	PIMAGE_SECTION_HEADER TempSectionHeader = pSectionHeader;
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		if (dwRva >= TempSectionHeader->VirtualAddress && dwRva <= (TempSectionHeader->VirtualAddress + TempSectionHeader->SizeOfRawData))
		{
			dwFov = TempSectionHeader->PointerToRawData + dwRva - TempSectionHeader->VirtualAddress;
			return dwFov;
		}
		TempSectionHeader++;
	}

	return 0;
}

DWORD FOA_TO_RVA(DWORD dwFoa)
{
	DWORD dwRva = 0;

	if (dwFoa < pOptionalHeader->SizeOfHeaders)
	{
		dwRva = dwFoa;
		return dwRva;
	}

	PIMAGE_SECTION_HEADER TempSectionHeader = pSectionHeader;
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		if (dwFoa >= TempSectionHeader->PointerToRawData && dwFoa <= (TempSectionHeader->PointerToRawData + TempSectionHeader->SizeOfRawData))
		{
			dwRva = TempSectionHeader->VirtualAddress + dwFoa - TempSectionHeader->PointerToRawData;
			return dwRva;
		}
		TempSectionHeader++;
	}

	return 0;
}

NTSTATUS LoadNtkrnlpa() 
{
	NTSTATUS						status = STATUS_SUCCESS;
	HANDLE							hFile = NULL;
	OBJECT_ATTRIBUTES				objAttr;
	IO_STATUS_BLOCK					ioBlock;
	UNICODE_STRING					FileName;
	FILE_STANDARD_INFORMATION		FileInfo;
	LARGE_INTEGER					Lageint; // 读取位置offset

	RtlInitUnicodeString(&FileName, FILEPATH);
	InitializeObjectAttributes(&objAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenFile(&hFile, FILE_ALL_ACCESS, &objAttr, &ioBlock, 0, FILE_NON_DIRECTORY_FILE);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ZwOpenFile Failed!, status:%d\n", status);
		return STATUS_UNSUCCESSFUL;
	}

	status = ZwQueryInformationFile(hFile, &ioBlock, &FileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		DbgPrint("ZwQueryInformationFile Failed!\n");
		return STATUS_UNSUCCESSFUL;
	}
	FileSize = FileInfo.EndOfFile.LowPart;
	pFileBuffer = ExAllocatePool(NonPagedPool, FileSize);

	Lageint.QuadPart = 0;
	status = ZwReadFile(hFile, NULL, NULL, NULL, &ioBlock, pFileBuffer, FileSize, &Lageint, NULL);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		DbgPrint("ZwReadFile Failed!\n");
		return STATUS_UNSUCCESSFUL;
	}

	ZwClose(hFile);
	// 读取PE信息
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		ExFreePool(pFileBuffer);
		pFileBuffer = NULL;
		DbgPrint("Read PE File Failed\n");
		return STATUS_UNSUCCESSFUL;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		ExFreePool(pFileBuffer);
		pFileBuffer = NULL;
		DbgPrint("Read PE File Failed\n");
		return STATUS_UNSUCCESSFUL;
	}

	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	pReloactionDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)pDosHeader + RVA_TO_FOA(pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
	pIATDirectory = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + RVA_TO_FOA(pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress));
	
	return status;
}

NTSTATUS FixRelocTable(DWORD OrignalImageBase)
{
	if (pReloactionDirectory == NULL) return STATUS_UNSUCCESSFUL;

	// 修复重定位表
	DWORD AddItem = OrignalImageBase - pOptionalHeader->ImageBase;
	// pOptionalHeader->ImageBase = NewImageBase;

	PIMAGE_BASE_RELOCATION pTempRelocationDir = pReloactionDirectory;
	UINT Count = 0;

	do
	{
		DWORD ChunkNum = (pTempRelocationDir->SizeOfBlock - 0x8) / 0x2;

		for (UINT i = 0; i < ChunkNum; i++)
		{
			PWORD pItem = (PWORD)(((DWORD)pTempRelocationDir + 0x8) + 0x2 * i);
			DWORD Type = (*pItem) >> 12;
			if (Type == 3)
			{
				PDWORD pFixAddress = (PDWORD)((DWORD)pDosHeader + RVA_TO_FOA(pTempRelocationDir->VirtualAddress + (*pItem & 0x0FFF)));
				*pFixAddress += AddItem;
			}
		}

		pTempRelocationDir = (PIMAGE_BASE_RELOCATION)((DWORD)pTempRelocationDir + pTempRelocationDir->SizeOfBlock);
		Count++;
	} while (pTempRelocationDir->VirtualAddress != 0 && pTempRelocationDir->SizeOfBlock != 0);

	// DbgPrint("FixBlockCount:%d\n", Count);
	return STATUS_SUCCESS;
}

NTSTATUS FixIATTable()
{
	PIMAGE_THUNK_DATA pTemIATDir = pIATDirectory;
	ULONG CopySize = 0;

	while (pTemIATDir->u1.Function != 0)
	{
		CopySize += 4;
		pTemIATDir++;
	}

	PULONG pCurrentIATDir = OrignImage + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
	RtlCopyMemory(pIATDirectory, pCurrentIATDir, CopySize);
	
	return STATUS_SUCCESS;
}

NTSTATUS CopyFileBufferToImageBuffer(_In_ LPVOID pFilebuffer_, _Out_ LPVOID* pImageBuffer_)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFilebuffer_;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFilebuffer_ + pDosHeader->e_lfanew);

	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

	DWORD AlignImageSize = Align(pOptionalHeader->SizeOfImage, pOptionalHeader->SectionAlignment);
	*pImageBuffer_ = ExAllocatePool(NonPagedPool, AlignImageSize);
	memset(*pImageBuffer_, 0, AlignImageSize);
	memcpy(*pImageBuffer_, pFilebuffer_, pOptionalHeader->SizeOfHeaders);

	PIMAGE_SECTION_HEADER TempSectionHeader = pSectionHeader;

	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		memcpy((LPVOID)((DWORD)*pImageBuffer_ + TempSectionHeader->VirtualAddress), (LPVOID)((DWORD)pDosHeader + TempSectionHeader->PointerToRawData), TempSectionHeader->SizeOfRawData);
		TempSectionHeader++;
	}

	return STATUS_SUCCESS;
}

NTSTATUS GetNtkrnlpaOrinalImage(PDRIVER_OBJECT pDriver)
{
	PLDR_DATA_TABLE_ENTRY pldr = (PLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	DWORD DllBaseSelf = pldr->DllBase;
	PLDR_DATA_TABLE_ENTRY pTempldr = pldr->InLoadOrderLinks.Blink;
	while (pTempldr->DllBase != DllBaseSelf)
	{
		if (pTempldr->DllBase != NULL)
		{
			UNICODE_STRING ModuleName;
			UNICODE_STRING ntoskrnlstr;

			ModuleName.Buffer = ExAllocatePool(NonPagedPool, 0x256);
			ModuleName.MaximumLength = 0x256;
			RtlCopyUnicodeString(&ModuleName, &pTempldr->BaseDllName);
			RtlInitUnicodeString(&ntoskrnlstr, L"ntoskrnl.exe");
			if (RtlCompareUnicodeString(&ntoskrnlstr, &ModuleName, FALSE) == 0)
			{
				OrignImage = pTempldr->DllBase;
				return STATUS_SUCCESS;
			}
			ExFreePool(ModuleName.Buffer);
		}
		pTempldr = pTempldr->InLoadOrderLinks.Blink;
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS SetNewSSDT(DWORD NewImageBase)
{

	pNewKeServiceDescriptorTable = (PKSERVICE_TABLE_DESCRIPTOR)((DWORD)KeServiceDescriptorTable - OrignImage + NewImageBase);

	// 函数表
	pNewKeServiceDescriptorTable->ntoskrnl.ServiceTableBase = (PULONG)((DWORD)KeServiceDescriptorTable->ntoskrnl.ServiceTableBase - OrignImage + NewImageBase);
	
	// 函数个数
	pNewKeServiceDescriptorTable->ntoskrnl.NumberOfService = KeServiceDescriptorTable->ntoskrnl.NumberOfService;

	// 调用次数
	// pNewKeServiceDescriptorTable->ntoskrnl.ServiceCounterTableBase = (PULONG)((DWORD)KeServiceDescriptorTable->ntoskrnl.ServiceCounterTableBase - OrignImage + NewImageBase);

	// 参数表
	pNewKeServiceDescriptorTable->ntoskrnl.ParamTableBase = (PULONG)((DWORD)KeServiceDescriptorTable->ntoskrnl.ParamTableBase - OrignImage + NewImageBase);

	 PageProtectOff();

	// 修复函数地址表 ,其实重定位表修复那里就修好了
	for (ULONG i = 0; i < pNewKeServiceDescriptorTable->ntoskrnl.NumberOfService; i++)
	{
		pNewKeServiceDescriptorTable->ntoskrnl.ServiceTableBase[i] += (-OrignImage + NewImageBase);

	}
	 PageProtectOn();

	return STATUS_SUCCESS;
}

NTSTATUS HookKiFastCallEntry()
{
	ULONG	HookAddr = 0;
	ULONG	uKiFastCallEntry = 0;
	// 找到KiFastCallEntry函数首地址, 在特殊模组寄存器的0x176号寄存器中
	__asm
	{
		push ecx;
		push eax;
		push edx;
		mov ecx, 0x176; // 设置编号
		rdmsr; ;// 读取到edx:eax
		mov uKiFastCallEntry, eax;// 保存到变量
		pop edx;
		pop eax;
		pop ecx;
	}

	for (ULONG i = 0; i < 0x1FF; ++i)
	{
		if (RtlCompareMemory((UCHAR*)uKiFastCallEntry + i, OriginalCode, 5) == 5)
		{
			HookAddr = uKiFastCallEntry + i;
			break;
		}
	}
	if (HookAddr == 0)
	{
		DbgPrint("Not Find 2be1c1e902 bytes");
		return STATUS_UNSUCCESSFUL;
	}

	PDWORD JmpAddr = (PDWORD)HookProc;

	PageProtectOff();
	DWORD32 X = (HookAddr + 5) - ((DWORD32)&OriginalCode[5] + 5);
	OriginalCode[5] = '\xE9';
	*(DWORD32*)(OriginalCode + 5 + 1) = X;
	pOrigianlCmd = (PORIGINALCOMD)(CHAR*)OriginalCode;
	BackAddr = HookAddr + 5;

	memset(NewCode, 0, 64);
	NewCode[0] = '\xE9';
	X = (DWORD32)JmpAddr - (HookAddr + 5);
	*(DWORD32*)(NewCode + 1) = (DWORD32)X;
	int Numnop = 5 - 5;
	for (int i = 0; i < Numnop; i++)
	{
		NewCode[5 + i] = '\x90';
	}

	RtlMoveMemory(HookAddr, NewCode, 5);

	PageProtectOn();

	return STATUS_SUCCESS;
}

NTSTATUS UnHookKiFastCallEntry()
{
	// 卸载hook
	if (BackAddr != 0)
	{
		PageProtectOff();
		RtlCopyMemory((PVOID)(BackAddr - 5), OriginalCode, 5);
		PageProtectOn();

		BackAddr = 0;
	}

	if (pFileBuffer != NULL)
	{
		ExFreePool(pFileBuffer);
		pFileBuffer = NULL;
	}
	if (pImageBuffer != NULL)
	{
		ExFreePool(pImageBuffer);
		pImageBuffer = NULL;
	}
	if (pNewImageBase != NULL)
	{
		ExFreePool(pNewImageBase);
		pNewImageBase = NULL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS ReloadKernel(PDRIVER_OBJECT pDriver)
{
	NTSTATUS status = STATUS_SUCCESS;
	DWORD    Size = 0;
	
	status = LoadNtkrnlpa();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("LoadNtkrnlpa Falied!\n");
		return STATUS_UNSUCCESSFUL;
	}

	Size = Align(pOptionalHeader->SizeOfImage, pOptionalHeader->SectionAlignment);
	pNewImageBase = ExAllocatePool(NonPagedPool, Size);
	RtlZeroMemory(pNewImageBase, Size);
	
	status = GetNtkrnlpaOrinalImage(pDriver);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("GetNtkrnlpaOrinalImage Falied!\n");
		return STATUS_UNSUCCESSFUL;
	}

	status = FixRelocTable((DWORD)OrignImage);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FixRelocTable Falied!\n");
		return STATUS_UNSUCCESSFUL;
	}

	status = FixIATTable();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FixIATTable Falied!\n");
		return STATUS_UNSUCCESSFUL;
	}

	status = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("CopyFileBufferToImageBuffer Falied!\n");
		return STATUS_UNSUCCESSFUL;
	}

	RtlCopyMemory(pNewImageBase, pImageBuffer, Size);
	ExFreePool(pImageBuffer);
	pImageBuffer = NULL;
	
	status = SetNewSSDT(pNewImageBase);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("SetNewSSDT Falied!\n");
		return STATUS_UNSUCCESSFUL;
	}

	status = HookKiFastCallEntry();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("HookKiFastCallEntry Falied!\n");
		return STATUS_UNSUCCESSFUL;
	}

	return status;
}