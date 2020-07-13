#include "Injection.h"

//Injected Shell Code
DWORD WINAPI LoadDll(PVOID p)
{
	PMANUAL_INJECT Inject;

	HMODULE hModule;
	DWORD	i, Function, count, delta;

	PDWORD	ptr;
	PWORD	list;

	PIMAGE_BASE_RELOCATION		pIBR;
	PIMAGE_IMPORT_DESCRIPTOR	pIID;
	PIMAGE_IMPORT_BY_NAME		pIBN;
	PIMAGE_OPTIONAL_HEADER		pIOH;
	PIMAGE_THUNK_DATA			FirstThunk, OrigFirstThunk;

	PDLL_MAIN EntryPoint;

	Inject = (PMANUAL_INJECT)p;

	pIBR = Inject->BaseRelocation;
	delta = (DWORD)((LPBYTE)Inject->ImageBase - Inject->NtHeaders->OptionalHeader.ImageBase);

	//Relocate the image
	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			//Calculate remaining values to change; 
			count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			list = (PWORD)(pIBR + 1);

			for (i = 0; i < count; i++)
			{
				//Only copy data that isn't NULL
				if (list[i])
				{
					ptr = (PDWORD)((LPBYTE)Inject->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		//Go to next struct 
		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);

		//Check valided IMAGE_BASE_RELOCATION struct
		if (!pIBR->VirtualAddress) {
			break;
		}
	}

	pIID = Inject->ImportDirectory;

	//Resolve DLL imports
	while (pIID->Characteristics)
	{
		//get original function addresses and pointers to the new function address data
		OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)Inject->ImageBase + pIID->OriginalFirstThunk);
		FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)Inject->ImageBase + pIID->FirstThunk);

		// Get INSTANCE of DLL import library
		hModule = Inject->fnLoadLibraryA((LPCSTR)Inject->ImageBase + pIID->Name);

		if (!hModule)
		{
			return FALSE;
		}

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal
				Function = (DWORD)Inject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			else
			{
				// Import by name

				pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)Inject->ImageBase + OrigFirstThunk->u1.AddressOfData);
				Function = (DWORD)Inject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			OrigFirstThunk++;
			FirstThunk++;
		}

		pIID++;
	}

	//TLS callbacks(Thread Local Storage)  
	//The Callbacks run before the injected DLL runs

	pIOH = &((PIMAGE_NT_HEADERS)((LPBYTE)Inject->ImageBase + ((PIMAGE_DOS_HEADER)Inject->ImageBase)->e_lfanew))->OptionalHeader;

	if (pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {

		//Find the TLS Callback list of function pointers
		PIMAGE_TLS_DIRECTORY pTLS = (PIMAGE_TLS_DIRECTORY)((LPBYTE)Inject->ImageBase + pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		PIMAGE_TLS_CALLBACK* pTCB = (PIMAGE_TLS_CALLBACK*)(pTLS->AddressOfCallBacks);

		//Call all the functions in the CALLBACKS
		for (; pTCB && *pTCB; ++pTCB) {
			(*pTCB)(Inject->ImageBase, DLL_PROCESS_ATTACH, NULL);
		}
	}

	if (Inject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		EntryPoint = (PDLL_MAIN)((LPBYTE)Inject->ImageBase + Inject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		return EntryPoint((HMODULE)Inject->ImageBase, DLL_PROCESS_ATTACH, NULL);
	}

	return TRUE;
}

DWORD WINAPI LoadDllEnd()
{
	return 0;
}