#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "Console.h"

Console console;

// This stub function contains the first instruction of the function that has the breakpoint on it. 
// Then it jumps one byte past the breakpoint address, where the next instruction starts. 
// This is needed because if EIP is not modified, the exception will be raised again once the handler finishes and an infinite loop will occur.
// To find the first instruction of the function you are replacing, you can use Ghidra. 
// Make sure you analyze the correct DLL (32-bit in SysWOW64 folder or 64-bit in System32 folder).
// Note: it should also be possible to dynamically copy the instructions at func_addr to execute them somewhere else
DWORD func_addr = NULL;
DWORD func_addr_offset = NULL;
void __declspec(naked) MessageBoxW_trampoline(void) {
	fprintf(console.stream, "before trampoline\n");
	__asm {
		mov edi, edi
		jmp[func_addr_offset]
	}
	fprintf(console.stream, "after trampoline\n");
}

// print parameters to console 
void print_parameters(PCONTEXT debug_context) {
	fprintf(console.stream, "EAX: %X EBX: %X ECX: %X EDX: %X\n",
		debug_context->Eax, debug_context->Ebx, debug_context->Ecx, debug_context->Edx);
	fprintf(console.stream, "ESP: %X EBP: %X\n",
		debug_context->Esp, debug_context->Ebp);
	fprintf(console.stream, "ESI: %X EDI: %X\n",
		debug_context->Esi, debug_context->Edi);

	//ESP is stack pointer, all parameters are on the stack
	fprintf(console.stream, "Parameters:\n");
	fprintf(console.stream, "HWND: %p\n", (HWND)(*(PDWORD)(debug_context->Esp + 0x4)));

	// MessageBoxW uses wide strings
	fwprintf(console.stream, L"lptext:    %s\n", (LPCWSTR)(*(PDWORD)(debug_context->Esp + 0x8)));
	fwprintf(console.stream, L"lpcaption: %s\n", (LPCWSTR)(*(PDWORD)(debug_context->Esp + 0xC)));

	fprintf(console.stream, "type: % X\n", (UINT)(*(PDWORD)(debug_context->Esp + 0x10)));
	// Example: 23h == MB_ICONQUESTION + MB_YESNOCANCEL
}

// To find parameters of the function you are replacing, you can use Ghidra.
void modify_text(PCONTEXT debug_context) {
	DWORD oldProtection{};
	VirtualProtect((LPVOID)(debug_context), 0x1000, PAGE_READWRITE, &oldProtection);
	fprintf(console.stream, "Changed Protection");

	//TODO: debug this, changes in stack causes crash
	//char* text = (char*)(*(DWORD*)(debug_context->Esp + 0x8));
	//int length = strlen(text);
	//_snfprintf(console.stream, text, length, "REPLACED");

	fprintf(console.stream, "Replaced text");
	VirtualProtect((LPVOID)(debug_context), 0x1000, oldProtection, &oldProtection);
	fprintf(console.stream, "Changed Protection");
}

// When an exception is raised, ExceptionFilter checks to see whether the exception occurred at the desired address.
// If so, the exception is handled and now the context record 
// (containing, among other things, the values of all registers and flags when the breakpoint was hit).
// Since the function sets up a standard BP - based frame, the parameters can all be retrieved through 
// ESP (since the stack frame was not set up yet when the breakpoint was hit). 
// All registers and parameters can then be inspected and/or modified as shown in print_parameters and modify_text.
LONG WINAPI ExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo) {
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
		if ((DWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress == func_addr) {
			PCONTEXT debug_context = ExceptionInfo->ContextRecord;
			fprintf(console.stream, "Breakpoint hit!\n");
			print_parameters(debug_context);

			fprintf(console.stream, "Modifying parameters on stack (not implemented).\n");
			//modify parameters on stack
			//modify_text(debug_context);

			fprintf(console.stream, "Using trampoline to go to instruction after breakpoint.\n");
			debug_context->Eip = (DWORD)&MessageBoxW_trampoline; //PAGE FAULT bij executing trampoline (op wine)
			//VirtualProtect() => proberen oplossen op Wine

			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}



// Use TH32Snapshot to iterate all threads on the system until we find the threads of the target proces. 
// We then select the oldest (main) thread of this process.
// The handle for this thread is kept so the debug registers can be set up. 
HANDLE getMainThread() {
	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hTool32 != INVALID_HANDLE_VALUE) {
		THREADENTRY32 thread_entry32;
		thread_entry32.dwSize = sizeof(THREADENTRY32);
		FILETIME exit_time, kernel_time, user_time;
		FILETIME creation_time;
		FILETIME prev_creation_time;
		prev_creation_time.dwLowDateTime = 0xFFFFFFFF;
		prev_creation_time.dwHighDateTime = INT_MAX;
		HANDLE hMainThread = NULL;
		if (Thread32First(hTool32, &thread_entry32)) {
			// Iterate all threads in the snapshot
			do {
				// Check if the thread is part of the current process
				if (thread_entry32.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(thread_entry32.th32OwnerProcessID)
					&& thread_entry32.th32OwnerProcessID == GetCurrentProcessId()
					&& thread_entry32.th32ThreadID != GetCurrentThreadId()) {

					// Get a handle to the thread					
					HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
						FALSE, thread_entry32.th32ThreadID);

					if (hThread != NULL) {
						// Check the creation time of the thread
						GetThreadTimes(hThread, &creation_time, &exit_time, &kernel_time, &user_time);

						// Replace the thread if we found an earlier created thread
						if (CompareFileTime(&creation_time, &prev_creation_time) == -1) {
							memcpy(&prev_creation_time, &creation_time, sizeof(FILETIME));
							if (hMainThread != NULL)
								CloseHandle(hMainThread);
							hMainThread = hThread;

						}
						else
							CloseHandle(hThread);

					}
				}
				thread_entry32.dwSize = sizeof(THREADENTRY32);
			} while (Thread32Next(hTool32, &thread_entry32));

		}
		CloseHandle(hTool32);

		return hMainThread;
	}
}

LPCSTR module_name = "user32.dll";
LPCSTR function_name = "MessageBoxW";
HANDLE h_main_thread = NULL;

// create a CONTEXT structure with ContextFlags CONTEXT_DEBUG_REGISTERS
// to access the debug registers: https://en.wikipedia.org/wiki/X86_debug_register
// - DR4 and DR5 are no longer used and their functionality is replaced with DR6 and DR7
// - DR0 to DR3 can each hold a linear address to break on depending on how the debug control register (DR7) is set.
// - The debug status(DR6) register lets a debugger determine which debug conditions have occurred.
CONTEXT thread_context = { CONTEXT_DEBUG_REGISTERS };

DWORD WINAPI testHook(PVOID base) {
	fprintf(console.stream, "Testing the hook ...\n");
	SetThreadContext(GetCurrentThread(), &thread_context);
	// Note: The pseudo handle need not be closed when it is no longer needed
	MessageBoxW(NULL, L"Testing the hook", L"Testing", MB_OK);

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		//The DisableThreadLibraryCalls function lets a DLL disable the DLL_THREAD_ATTACH and DLL_THREAD_DETACH notification calls.
		// This can be a useful optimization for multithreaded applications that have many DLLs, frequently createand delete threads, 
		// and whose DLLs do not need these thread - level notifications of attachment/detachment.
		DisableThreadLibraryCalls(hModule);

		if (!console.open()) {
			// Indicate DLL loading failed
			return FALSE;
		}

		// Find the address of the true Function
		HMODULE h_module = GetModuleHandleA(module_name);
		if (h_module == NULL) {
			fprintf(console.stream, "Unable to retrieve handle for module %s\n", module_name);
			return FALSE;
		}
		func_addr = (DWORD)GetProcAddress(h_module, function_name);
		func_addr_offset = func_addr + 0x2; // jump over first instruction (instruction 'mov edi, edi' is 2 bytes long => view in Ghidra)

		// Search the main thread
		h_main_thread = getMainThread();
		if (h_main_thread == NULL) {
			fprintf(console.stream, "Unable to retrieve handle for main thread\n");
			return FALSE;
		}

		// Set the exception filter
		fprintf(console.stream, "Setting Exception Filter.\n");
		(void)SetUnhandledExceptionFilter(ExceptionFilter);
		// AddVectoredExceptionHandler

		// Set debug registers in thread context to trigger exception
		fprintf(console.stream, "Setting breakpoint in Dr registers.\n");


		thread_context.Dr0 = func_addr; // DR0 is set to the desired address (address of MessageBoxW)
		thread_context.Dr7 = (1 << 0); // DR7 is set to a local enable level for the address in DR0

		SetThreadContext(h_main_thread, &thread_context);
		// Removing the breakpoints is as simple as clearing the debug registers in the main thread.

		// Test: also set for this thread and call function
		CreateThread(nullptr, NULL, testHook, hModule, NULL, nullptr);

	}

	case DLL_THREAD_ATTACH: break;
	case DLL_THREAD_DETACH: break;
	case DLL_PROCESS_DETACH: {
		fprintf(console.stream, "Uninstalling the hook ...\n");

		thread_context = { CONTEXT_DEBUG_REGISTERS };
		SetThreadContext(h_main_thread, &thread_context);

		(void)SetUnhandledExceptionFilter(NULL);
		// RemoveVectoredExceptionHandler

		CloseHandle(h_main_thread);

		// Open a MessageBox to allow reading the output
		MessageBoxW(NULL, L"Press Ok to close", L"Closing", NULL);
	}
	}
	return TRUE;
}

