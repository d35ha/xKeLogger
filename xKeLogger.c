#include <wdm.h>
#include <stdlib.h>

// this is a very basic kernel logger for NtCreateFile
// to be used a user mode process should invoke DeviceIoControl passing the target process id
// here's an example

/*
		#include <windows.h>
		#include <stdio.h>

		#define KERNEL_LOGGER_DRIVER 0x8008
		#define IOCTL_MONITOR_PROCESS (ULONG) CTL_CODE	(\
			KERNEL_LOGGER_DRIVER, \
			0x00, \
			METHOD_BUFFERED,\
			FILE_ANY_ACCESS \
		)

		int _cdecl main(INT argc, PCHAR* argv)
		{
			if (argc < 2)
			{
				printf("%s PID\n", argv[0]); // the process id is passed as parameter
				return 1;
			};

			HANDLE hFile;
			DWORD dwReturn;
			UINT_PTR pID = atoi(argv[1]);

			hFile = CreateFileA("\\\\.\\LoggerDevice",
				GENERIC_READ | GENERIC_WRITE, 0, NULL,
				OPEN_EXISTING, 0, NULL);

			if (hFile)
			{
				DeviceIoControl(hFile,
					IOCTL_MONITOR_PROCESS,
					&pID,
					sizeof(UINT_PTR),
					NULL,
					0,
					&dwReturn,
					(LPOVERLAPPED)NULL
				);
				CloseHandle(hFile);
			};

			return 0;
		};
*/

// for now the logs will be transmitted via DbgPrint

// define the type of the driver (any value > 0x8000)
#define KERNEL_LOGGER_DRIVER 0x8008 
#define MAX_PATH 260 

// prototypes
VOID DriverUnload(PDRIVER_OBJECT  DriverObject);
NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath);
NTSTATUS IrpHandler(PDEVICE_OBJECT  pDeviceObject, PIRP  pIrp);

// to avoid C4100
#define DUMMY_PARAM(PARAM) PARAM

// definition of the IOCTLs to be used
// to log all of the calls made to NtCreateFile that are invoked by a processs
#define IOCTL_MONITOR_PROCESS (ULONG) CTL_CODE	(\
	KERNEL_LOGGER_DRIVER, \
	0x00, \
	METHOD_BUFFERED,\
	FILE_ANY_ACCESS \
)

// used apis routines (to directly convert PVOID to a function with params)
#define ZwQueryInformationProcessRoutine(fnZwQueryInformationProcess) \
(*(NTSTATUS(__kernel_entry*)( \
	HANDLE, \
	PROCESSINFOCLASS, \
	PVOID, \
	ULONG, \
	PULONG)) fnZwQueryInformationProcess \
)

#define NtCreateFileRoutine(fnNtCreateFile) \
(*(NTSTATUS(__kernel_entry*)( \
		PHANDLE, \
		ACCESS_MASK, \
		POBJECT_ATTRIBUTES, \
		PIO_STATUS_BLOCK, \
		PLARGE_INTEGER, \
		ULONG, \
		ULONG, \
		ULONG, \
		ULONG, \
		PVOID, \
		ULONG)) fnNtCreateFile \
) 

#define ObOpenObjectByPointerRoutine(fnObOpenObjectByPointer) \
(*(NTSTATUS(__kernel_entry*)( \
		PVOID, \
		ULONG, \
		PACCESS_STATE, \
		ACCESS_MASK, \
		POBJECT_TYPE, \
		KPROCESSOR_MODE, \
		PHANDLE)) fnObOpenObjectByPointer \
) 

// undefined types 
typedef PVOID PPEB; // PEB is not used at this driver

// SSDT
typedef struct _KSERVICE_DESCRIPTOR_TABLE
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
}KSERVICE_DESCRIPTOR_TABLE, * PKSERVICE_DESCRIPTOR_TABLE;

// SYSTEM_INFORMATION_CLASS
typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	// truncated
	ProcessImageFileName = 27
	// truncated
} PROCESSINFOCLASS;

// ROCESS_BASIC_INFORMATION
typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

// hook info
typedef struct _HOOK_INFO
{ 
	PVOID OriginalApi;
	PVOID* lpApiSSDT;
	PVOID ApiBuffer; // you can use the value directly (like storing a process id) 
					 // or you can store the address of an allocated memory
	BOOLEAN IsHooked;
} HOOK_INFO, * PHOOK_INFO;

// hooked apis
HOOK_INFO NtCreateFileHook = { 0 };

// needed apis (initialized at driver loading)
PVOID ZwQueryInformationProcess;
PVOID ObOpenObjectByPointer;

// initialize needed apis
NTSTATUS ReolveApi(PWCH uzApiName, PVOID* lpApiPointer)
{
	UNICODE_STRING StrApi;
	RtlInitUnicodeString(&StrApi,
		uzApiName);

	PVOID ApiAddress = MmGetSystemRoutineAddress(
		&StrApi
	);

	if (!ApiAddress)
		return STATUS_NOT_FOUND;

	memcpy(
		lpApiPointer,
		&ApiAddress,
		sizeof(PVOID)
	);

	return STATUS_SUCCESS;
};

// hooked NtCreateFile
__kernel_entry NTSTATUS HookedNtCreateFile(
	OUT PHANDLE           FileHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN PLARGE_INTEGER     AllocationSize,
	IN ULONG              FileAttributes,
	IN ULONG              ShareAccess,
	IN ULONG              CreateDisposition,
	IN ULONG              CreateOptions,
	IN PVOID              EaBuffer,
	IN ULONG              EaLength
) {

	// getting a pointer to the current process handle
	BOOLEAN LogCurrentCall = FALSE;
	HANDLE hProcess = NULL;
	NTSTATUS NtStatus = ObOpenObjectByPointerRoutine(ObOpenObjectByPointer)(
		IoGetCurrentProcess(),
		OBJ_KERNEL_HANDLE,
		NULL,
		GENERIC_READ,
		NULL,
		KernelMode,
		&hProcess
	);

	if (NT_SUCCESS(NtStatus)) {

		PROCESS_BASIC_INFORMATION ProcessInfo = { 0 };
		ULONG ulRetLength = 0;

		// getting the pid of the current process
		NtStatus = ZwQueryInformationProcessRoutine(ZwQueryInformationProcess)(
				hProcess,
				ProcessBasicInformation,
				&ProcessInfo,
				sizeof(ProcessInfo),
				&ulRetLength
				);

		// check if the target process is the current process
		if (NT_SUCCESS(NtStatus) &&
			ProcessInfo.UniqueProcessId == (UINT_PTR)NtCreateFileHook.ApiBuffer)
		{
			// the currently logging level is
			/*
				[ProcessName] ApiName (
					ParamType0 Param0 = Value0,
					ParamType1 Param1 = Value1,
					ParamType2 Param2 = Value2,
					..         ..       ..
				) -> RetStatus;
			*/
			// this can be easily modified to include more information
			// like the calling module (this will enable us with a huge abaility)
			// the structs/unions/flags/enums members values (a lot of pain)
			// also the Last Status (if the call succeded or not), time difference, ...

			// getting the current process name

			WCHAR ProcessNameBuffer[sizeof(UNICODE_STRING) / sizeof(WCHAR) + MAX_PATH] = { 0 };
			PUNICODE_STRING ProcessName = (PUNICODE_STRING)ProcessNameBuffer;
			ProcessName->Buffer = &ProcessNameBuffer[sizeof(UNICODE_STRING) / sizeof(WCHAR)];
			ProcessName->MaximumLength = MAX_PATH * sizeof(WCHAR);
			ProcessName->Length = 0x0;

			NtStatus = ZwQueryInformationProcessRoutine(ZwQueryInformationProcess)(
				hProcess,
				ProcessImageFileName,
				&ProcessNameBuffer,
				sizeof(ProcessNameBuffer),
				&ulRetLength
				);

			if (NT_SUCCESS(NtStatus))

				// maximum transmitted buffer length is 512 bytes
				// use kdbgctrl to adjust it to be 
				// using DbgPrint is temporary because the logs
				// should be handed to the process that invoked the IOCTL

				DbgPrint(
					"[%wZ] NtCreateFile(\r\n"
					"		PHANDLE			    FileHandle = 0x%p,\r\n"
					"		ACCESS_MASK			DesiredAccess = 0x%lx,\r\n"
					"		POBJECT_ATTRIBUTES  ObjectAttributes = 0x%p,\r\n"
					"		PIO_STATUS_BLOCK	IoStatusBlock = 0x%p,\r\n"
					"		PLARGE_INTEGER		AllocationSize = 0x%p,\r\n"
					"		ULONG				FileAttributes = 0x%lx,\r\n"
					"		ULONG				ShareAccess = 0x%lx,\r\n"
					"		ULONG				CreateDisposition = 0x%lx,\r\n"
					"		ULONG				CreateOptions = 0x%lx,\r\n"
					"		PVOID				EaBuffer = 0x%p,\r\n"
					"		ULONG				EaLength = 0x%lx\r\n"
					")",
					ProcessName,
					FileHandle,
					DesiredAccess,
					ObjectAttributes,
					IoStatusBlock,
					AllocationSize,
					FileAttributes,
					ShareAccess,
					CreateDisposition,
					CreateOptions,
					EaBuffer,
					EaLength
				);
			LogCurrentCall = TRUE;
		};

		ZwClose(hProcess);
	};

	NtStatus = NtCreateFileRoutine(NtCreateFileHook.OriginalApi)(
			FileHandle,
			DesiredAccess,
			ObjectAttributes,
			IoStatusBlock,
			AllocationSize,
			FileAttributes,
			ShareAccess,
			CreateDisposition,
			CreateOptions,
			EaBuffer,
			EaLength
			);

	if (LogCurrentCall)
		DbgPrint(
			" -> 0x%lx\r\n", NtStatus
		);

	return NtStatus;
};

NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath)
{
	DUMMY_PARAM(pRegistryPath);
	NTSTATUS NtStatus = STATUS_SUCCESS;
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING usDriverName, usDosDeviceName;

	// use `ed nt!Kd_Default_Mask 8` at windbg to capture DbgPrint
	DbgPrint("Loading the driver \r\n");

	RtlInitUnicodeString(&usDriverName, L"\\Device\\LoggerDevice");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\LoggerDevice");

	NtStatus = IoCreateDevice(
		pDriverObject,
		0,
		&usDriverName,
		KERNEL_LOGGER_DRIVER,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&pDeviceObject
	);

	if (NtStatus == STATUS_SUCCESS)
	{

		// MajorFunction is a list of pointers indexed with IRP_MJ_** 
		// each one will be called when accessed with the proper IRP
		for (INT Index = 0; Index <= IRP_MJ_MAXIMUM_FUNCTION; Index++)
			pDriverObject->MajorFunction[Index] = IrpHandler;

		// set the unloader
		pDriverObject->DriverUnload = DriverUnload;

		// set the I/O type
		pDeviceObject->Flags |= DO_BUFFERED_IO;
		pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);

		// Create a symbolic Link to the device
		IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);
	};

	// initialization of the needed apis
	NtStatus = ReolveApi(
		L"ZwQueryInformationProcess", 
		&ZwQueryInformationProcess
	);

	if (!NT_SUCCESS(NtStatus))
		return NtStatus;

	NtStatus = ReolveApi(
		L"ObOpenObjectByPointer",
		&ObOpenObjectByPointer
	);

	if (!NT_SUCCESS(NtStatus))
		return NtStatus;

	return NtStatus;
};

VOID DriverUnload(PDRIVER_OBJECT  DriverObject)
{
	if (NtCreateFileHook.IsHooked) {
		DbgPrint("Unhooking NtCreateFile \r\n");
		*NtCreateFileHook.lpApiSSDT = NtCreateFileHook.OriginalApi;
		NtCreateFileHook.IsHooked = FALSE;
	};

	DbgPrint("Unloading the driver \r\n");

	UNICODE_STRING usDosDeviceName;
	RtlInitUnicodeString(&usDosDeviceName,
		L"\\DosDevices\\LoggerDevice");

	// delete the symbolic link
	IoDeleteSymbolicLink(&usDosDeviceName);
	// delete the device
	IoDeleteDevice(DriverObject->DeviceObject);
};

NTSTATUS IrpHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	DUMMY_PARAM(DeviceObject);
	NTSTATUS NtStatus = STATUS_SUCCESS;
	UNICODE_STRING KeServiceDescriptorTable = { 0 };
	PKSERVICE_DESCRIPTOR_TABLE lpSSDT = NULL;
	PVOID* NtApisArray = NULL;
	INT Index = 0;

	// get the IRP message invoked
	PIO_STACK_LOCATION pIoStckLoc = IoGetCurrentIrpStackLocation(Irp);

	if (!pIoStckLoc)
	{
		DbgPrint("Cannot read the IRP code \r\n");
		return STATUS_NOT_SUPPORTED;
	};

	switch (pIoStckLoc->MajorFunction)
	{
	case(IRP_MJ_CREATE):
	case(IRP_MJ_CLOSE):
	case(IRP_MJ_CLEANUP):
		return STATUS_SUCCESS;
	};

	if (pIoStckLoc->MajorFunction != IRP_MJ_DEVICE_CONTROL)
	{
		DbgPrint("Only IRP_MJ_DEVICE_CONTROL is accepted \r\n");
		return STATUS_INVALID_PARAMETER;
	};

	// getting the address of KeServiceDescriptorTable
	RtlInitUnicodeString(&KeServiceDescriptorTable,
		L"KeServiceDescriptorTable");

	lpSSDT = (PKSERVICE_DESCRIPTOR_TABLE)MmGetSystemRoutineAddress(
		&KeServiceDescriptorTable
	);

	if (!lpSSDT)
	{
		DbgPrint("Cannot get the address of the SSDT \r\n");
		NtStatus = STATUS_NOT_FOUND;
		goto SAFE_RETURN;
	};

	DbgPrint("Found ServiceTableBase at 0x%p \r\n",
		(PVOID)lpSSDT->ServiceTableBase);
	NtApisArray = (PVOID*)lpSSDT->ServiceTableBase;

	switch (pIoStckLoc->Parameters.DeviceIoControl.IoControlCode)
	{
	case (IOCTL_MONITOR_PROCESS):

		DbgPrint("IOCTL Operation: IOCTL_MONITOR_PROCESS \r\n");

		// expecting buffer of sizeof(UINT_PTR) as the process pid
		if (pIoStckLoc->Parameters.DeviceIoControl.InputBufferLength
			!= sizeof(ULONG_PTR))
		{
			DbgPrint("Invalid process id buffer \r\n");
			NtStatus = STATUS_INVALID_PARAMETER;
			goto SAFE_RETURN;
		};

		// check if already hooked
		if (NtCreateFileHook.IsHooked)
		{
			memcpy(&NtCreateFileHook.ApiBuffer,
				Irp->AssociatedIrp.SystemBuffer,
				sizeof(ULONG_PTR)
			);
			break;
		};

		// getting the address of NtCreateFile
		UNICODE_STRING StrNtCreateFile;
		RtlInitUnicodeString(&StrNtCreateFile,
			L"NtCreateFile");

		PVOID fnNtCreateFile;
		fnNtCreateFile = MmGetSystemRoutineAddress(
			&StrNtCreateFile
		);

		DbgPrint("Found NtCreateFile at 0x%p \r\n",
			fnNtCreateFile);

		for (Index = 0;
			fnNtCreateFile != NtApisArray[Index];
			Index++);
		NtCreateFileHook.OriginalApi = NtApisArray[Index];
		NtCreateFileHook.lpApiSSDT = &NtApisArray[Index];
		DbgPrint("Found NtCreateFile address at index %d in the SSDT \r\n",
			Index);

		// hooking NtCreateFile
		NtApisArray[Index] = (PVOID)HookedNtCreateFile;
		DbgPrint("NtCreateFile patched to be the hooked one at 0x%p \r\n",
			HookedNtCreateFile);

		memcpy(&NtCreateFileHook.ApiBuffer,
			Irp->AssociatedIrp.SystemBuffer,
			sizeof(ULONG_PTR)
		);

		NtCreateFileHook.IsHooked = TRUE;

		break;
	default:
		DbgPrint("Undefined IOCTL code \r\n");
		NtStatus = STATUS_INVALID_DEVICE_REQUEST;
	};

SAFE_RETURN:
	Irp->IoStatus.Status = NtStatus;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return NtStatus;
};