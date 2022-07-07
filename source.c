#include <stdio.h>
#include <windows.h>
#include <string.h>

int WINAPI NewMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
	printf("후킹!!! 성공\n");
	HMODULE hMod = GetModuleHandle("user32.dll");
	PROC MessageFunc = GetProcAddress(hMod, "MessageBoxA");
	MessageFunc(hWnd, "Hooking!", "Hook", uType); 
	return 0;	
}

void hook() {
	PBYTE hMod = (PBYTE)GetModuleHandle(NULL), HookAddress = NULL; // 현재 프로세스의 ImageBase 
	
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER) hMod; // Image Dos Header 구조체 
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS) ((PBYTE)hMod + dos->e_lfanew); // Image NT Header 구조체 
	PIMAGE_OPTIONAL_HEADER optional = (PIMAGE_OPTIONAL_HEADER) ((PBYTE)&nt->OptionalHeader); // Image Optional Header 구조체 
	PIMAGE_IMPORT_DESCRIPTOR import = (PIMAGE_IMPORT_DESCRIPTOR) ((PBYTE) hMod + optional->DataDirectory[1].VirtualAddress); // Image Import Descriptor 구조체 
	
	printf("DOS : 0x%x\n", dos);
	printf("NT : 0x%x\n", nt);
	printf("OPTIONAL : 0x%x\n", optional);
	printf("DESCRIPTOR : 0x%x\n", import);
	printf("THUNK : 0x%x\n", hMod + import->OriginalFirstThunk);
	
	while( import->Name ) {
		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA) ((PBYTE) hMod + import->OriginalFirstThunk), FirstThunk = (PIMAGE_THUNK_DATA) ((PBYTE) hMod + import->FirstThunk);
		char* dll = (char*)(import->Name + hMod);
		//printf("===[ %s ]===\n", dll);
		//printf(" FuncName => Address\n", dll);
		while( thunk->u1.Function ) {
			PIMAGE_IMPORT_BY_NAME name = (PIMAGE_IMPORT_BY_NAME) ((DWORD) thunk->u1.AddressOfData + hMod);
			char* func = (char *) ((PBYTE) name->Name);
			
			if( strcmp(func, "MessageBoxA") == 0 ){
				HookAddress = (PBYTE) &(FirstThunk->u1.Function);
				DWORD oldProtect;
				VirtualProtect((LPVOID)HookAddress, 8, PAGE_READWRITE, &oldProtect); 
				FirstThunk->u1.Function = (DWORD_PTR)NewMessageBox;
				printf("[+] Found %s!! => 0x%x\n", func, HookAddress);
				printf("[+] Hook Function Address : 0x%x\n", NewMessageBox);
				printf("[+] Change Address : 0x%x\n", FirstThunk->u1.Function);
				break;
			}
			
			//printf("[+] %s => 0x%x\n", func, (PBYTE)func);
			thunk++;
		}
		
		if( HookAddress != NULL)
			break;
		
		import++;
	}
}
int main() {
	hook();
	MessageBoxA(NULL, "HELLO", "hello", MB_OK);
	return 0;
}
