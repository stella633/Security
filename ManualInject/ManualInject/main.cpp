#include "Injection.h"

char Dll[] = "C:\\Users\\ktg73\\source\\repos\\ApiHook\\ApiHook\\kakao.dll";
char Exe[] = "Taskmgr.exe";

//Get processid
DWORD GetProcessId() {
	HANDLE			hTargetProcess = NULL;
	PROCESSENTRY32	pEntry32 = { sizeof(PROCESSENTRY32) };
	DWORD			dwProcessID = NULL;

	while (!dwProcessID) {
		//Access all running processes
		hTargetProcess = CreateToolhelp32Snapshot(PROCESS_ALL_ACCESS, 0);

		if (Process32First(hTargetProcess, &pEntry32)) {

			//Search process list for get processid
			do {
				if (!strcmp(pEntry32.szExeFile, Exe)) {
					dwProcessID = pEntry32.th32ProcessID;
					break;
				}

			} while (Process32Next(hTargetProcess, &pEntry32));

		}

	}

	CloseHandle(hTargetProcess);

	return dwProcessID;
}

int wmain(int argc, wchar_t* argv[])
{
	PIMAGE_DOS_HEADER		pIDH;
	PIMAGE_NT_HEADERS		pINH;
	PIMAGE_SECTION_HEADER	pISH;

	HANDLE	hProcess, hThread, hFile, hToken;
	PVOID	buffer, image, Memory;
	DWORD	i, FileSize, ProcessId, ExitCode, read;

	TOKEN_PRIVILEGES	tp;
	MANUAL_INJECT		ManualInject;

	//Set debugging privs
	if (OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		tp.Privileges[0].Luid.LowPart = 20;
		tp.Privileges[0].Luid.HighPart = 0;

		AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
		CloseHandle(hToken);
	}

	printf("\nOpening the DLL.\n");
	hFile = CreateFile(Dll, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("\nError: Unable to open the DLL (%d)\n", GetLastError());
		return -1;
	}

	//Allocate space for dll
	FileSize = GetFileSize(hFile, NULL);
	buffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!buffer)
	{
		printf("\nError: Unable to allocate memory for DLL data (%d)\n", GetLastError());

		CloseHandle(hFile);
		return -1;
	}

	//Read the DLL to memory

	if (!ReadFile(hFile, buffer, FileSize, &read, NULL))
	{
		printf("\nError: Unable to read the DLL (%d)\n", GetLastError());

		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hFile);

		return -1;
	}

	CloseHandle(hFile);

	//Access DOS HEADER 
	//Check MZ executable(Valid windows executable)
	pIDH = (PIMAGE_DOS_HEADER)buffer;

	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("\nError: Invalid executable image.\n");

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	//Access NT HEADERS
	//Check for NT signature and DLL Signature
	pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);

	if (pINH->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("\nError: Invalid PE header.\n");

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	if (!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL))
	{
		printf("\nError: The image is not DLL.\n");

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	//Open target process handle
	ProcessId = GetProcessId();

	printf("\nOpening target process.\n");
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

	if (!hProcess)
	{
		printf("\nError: Unable to open target process (%d)\n", GetLastError());

		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		return -1;
	}

	//Allocate space in target for DLL
	printf("\nAllocating memory for the DLL.\n");
	image = VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!image)
	{
		printf("\nError: Unable to allocate memory for the DLL (%d)\n", GetLastError());

		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		return -1;
	}

	//Copy the header to target process
	printf("\nCopying headers into target process.\n");

	if (!WriteProcessMemory(hProcess, image, buffer, pINH->OptionalHeader.SizeOfHeaders, NULL))
	{
		printf("\nError: Unable to copy headers to target process (%d)\n", GetLastError());

		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	//Copy sections table to memory
	pISH = (PIMAGE_SECTION_HEADER)(pINH + 1);

	printf("\nCopying sections to target process.\n");

	for (i = 0; i < pINH->FileHeader.NumberOfSections; i++)
	{
		WriteProcessMemory(hProcess, (PVOID)((LPBYTE)image + pISH[i].VirtualAddress), (PVOID)((LPBYTE)buffer + pISH[i].PointerToRawData), pISH[i].SizeOfRawData, NULL);
	}

	//Allocate space for shellcode
	printf("\nAllocating memory for the loader code.\n");
	Memory = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!Memory)
	{
		printf("\nError: Unable to allocate memory for the loader code (%d)\n", GetLastError());

		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	//DLL inject!
	printf("\nLoader code allocated at %#x\n", Memory);
	memset(&ManualInject, 0, sizeof(MANUAL_INJECT));

	ManualInject.ImageBase = image;
	ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew);
	ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	ManualInject.fnLoadLibraryA = LoadLibraryA;
	ManualInject.fnGetProcAddress = GetProcAddress;

	printf("\nWriting loader code to target process.\n");

	WriteProcessMemory(hProcess, Memory, &ManualInject, sizeof(MANUAL_INJECT), NULL); // Write the loader information to target process
	WriteProcessMemory(hProcess, (PVOID)((PMANUAL_INJECT)Memory + 1), LoadDll, (DWORD)LoadDllEnd - (DWORD)LoadDll, NULL); // Write the loader code to target process

	printf("\nExecuting loader code.\n");
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((PMANUAL_INJECT)Memory + 1), Memory, 0, NULL); // Create a remote thread to execute the loader code
	if (!hThread)
	{
		printf("\nError: Unable to execute loader code (%d)\n", GetLastError());

		VirtualFreeEx(hProcess, Memory, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);

		CloseHandle(hProcess);

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	//release 
	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, &ExitCode);

	if (!ExitCode)
	{
		VirtualFreeEx(hProcess, Memory, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);

		CloseHandle(hThread);
		CloseHandle(hProcess);

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	CloseHandle(hThread);
	VirtualFreeEx(hProcess, Memory, 0, MEM_RELEASE);

	CloseHandle(hProcess);

	printf("\nDLL injected at %#x\n", image);

	if (pINH->OptionalHeader.AddressOfEntryPoint)
	{
		printf("\nDLL entry point: %#x\n", (PVOID)((LPBYTE)image + pINH->OptionalHeader.AddressOfEntryPoint));
	}

	//free
	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}