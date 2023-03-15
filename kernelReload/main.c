/*
	踩坑:不能直接修复重定位表为新内核偏移，重定位表要先修为老内核偏移，再把SSDT里面函数地址修正为新内核的
	原因:我们只用新内核的函数，全局变量还是用老内核的 
*/

#include <ntddk.h>
#include <ntstatus.h>
#include "ntkrnlpaReload.h"


VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	UNREFERENCED_PARAMETER(pDriver); // 这句可有可无, 告诉编译器已经使用了变量不必警告
	UnHookKiFastCallEntry();

	DbgPrint("DriverUnload...\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING reg_path)
{
	DbgPrint("Driver is installed...\n");
	NTSTATUS status = STATUS_SUCCESS;
	pDriver->DriverUnload = DriverUnload;
	
	status = ReloadKernel(pDriver);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("----- ReloadKernel Falied -----\n");
	}

	return STATUS_SUCCESS;
}