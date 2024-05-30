#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "Console.h"

Console console;

// This stub function contains the first instruction of the function with the breakpoint
// => then the function jumps to the second instruction of the original function
// => this way we execute every instruction of the original function without triggering another exception and an infinite loop
DWORD func_addr = NULL;
DWORD func_addr_offset = NULL;
void __declspec(naked) MessageBoxW_trampoline(void)
{
	__asm {
		mov edi, edi
		jmp[func_addr_offset]
	}
	// Note: To find the first instruction of the hook function, you can use documentation (if available) or Ghidra
	// => Make sure you analyze the correct DLL (32-bit in SysWOW64 folder or 64-bit in System32 folder).
	// Note: it should also be possible to dynamically copy the instructions at func_addr instead of hardcoding it in assembly here
}

// print the content of the registers and the stack to the console
void print_parameters(PCONTEXT debug_context)
{
	fprintf(console.stream, "Registers:\n");
	fprintf(console.stream, "EAX: %X EBX: %X\n", debug_context->Eax, debug_context->Ebx);
	fprintf(console.stream, "ECX: %X EDX: %X\n", debug_context->Ecx, debug_context->Edx);
	fprintf(console.stream, "ESP: %X EBP: %X\n", debug_context->Esp, debug_context->Ebp);
	fprintf(console.stream, "ESI: %X EDI: %X\n", debug_context->Esi, debug_context->Edi);

	// ESP is the stack pointer, all parameters are on the stack
	// To find the parameters, you can use documentation (if available) or a decompiler like Ghidra.
	fprintf(console.stream, "Function parameters:\n");
	fprintf(console.stream, "HWND: %p\n", (HWND)(*(PDWORD)(debug_context->Esp + 0x4)));

	// MessageBoxW uses wide strings
	fwprintf(console.stream, L"lptext:    %s\n", (LPCWSTR)(*(PDWORD)(debug_context->Esp + 0x8)));
	fwprintf(console.stream, L"lpcaption: %s\n", (LPCWSTR)(*(PDWORD)(debug_context->Esp + 0xC)));

	fprintf(console.stream, "type: % X\n", (UINT)(*(PDWORD)(debug_context->Esp + 0x10)));
	// Example: 23h == MB_ICONQUESTION + MB_YESNOCANCEL
}

// Change the stack to update the caption shown in the MessageBox
LPCWSTR hook_caption = L"Hooked MessageBox";
void modify_stack(PCONTEXT debug_context)
{
	DWORD oldProtection{};
	VirtualProtect((LPVOID)(debug_context->Esp + 0xC), sizeof(PDWORD), PAGE_READWRITE, &oldProtection);
	*(PDWORD)(debug_context->Esp + 0xC) = (DWORD)hook_caption;
	VirtualProtect((LPVOID)(debug_context->Esp + 0xC), sizeof(PDWORD), oldProtection, &oldProtection);
}

// Used to pass to the Structured/Vectored Exception Handler
LONG WINAPI ExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)
{
	// Check if the ExceptionFilter caught the exception of the Debug Register or another unrelated exception
	// The Debug registers cause an EXCEPTION_SINGLE_STEP
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		// Check if the address of the exception matches the address of the hooked function
		if ((DWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress == func_addr)
		{
			// Use the ContextRecord to view/modify the arguments of the hooked function
			PCONTEXT debug_context = ExceptionInfo->ContextRecord;
			fprintf(console.stream, "Breakpoint hit, reading registers and function parameters ...\n");
			print_parameters(debug_context);

			fprintf(console.stream, "Modifying parameters on stack\n");
			modify_stack(debug_context);

			fprintf(console.stream, "Using trampoling\n");
			debug_context->Eip = (DWORD)&MessageBoxW_trampoline;

			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

// Use TH32Snapshot to iterate all threads on the system until we find the threads of the target proces.
// We then select the oldest (main) thread of this process.
// The handle for this thread is kept so the debug registers can be set up.
HANDLE getMainThread()
{
	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hTool32 != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 thread_entry32;
		thread_entry32.dwSize = sizeof(THREADENTRY32);
		FILETIME exit_time, kernel_time, user_time;
		FILETIME creation_time;
		FILETIME prev_creation_time;
		prev_creation_time.dwLowDateTime = 0xFFFFFFFF;
		prev_creation_time.dwHighDateTime = INT_MAX;
		HANDLE hMainThread = NULL;
		if (Thread32First(hTool32, &thread_entry32))
		{
			// Iterate all threads in the snapshot
			do
			{
				// Check if the thread is part of the current process
				if (thread_entry32.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(thread_entry32.th32OwnerProcessID) && thread_entry32.th32OwnerProcessID == GetCurrentProcessId() && thread_entry32.th32ThreadID != GetCurrentThreadId())
				{

					// Get a handle to the thread
					HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
												FALSE, thread_entry32.th32ThreadID);

					if (hThread != NULL)
					{
						// Check the creation time of the thread
						GetThreadTimes(hThread, &creation_time, &exit_time, &kernel_time, &user_time);

						// Replace the thread if we found an earlier created thread
						if (CompareFileTime(&creation_time, &prev_creation_time) == -1)
						{
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
CONTEXT thread_context = {CONTEXT_DEBUG_REGISTERS};

DWORD WINAPI testHook(PVOID base)
{
	fprintf(console.stream, "Testing the hook ...\n");
	SetThreadContext(GetCurrentThread(), &thread_context);
	// Note: The pseudo handle need not be closed when it is no longer needed
	MessageBoxW(NULL, L"Testing the hook", L"Testing", MB_OK);

	return 0;
}

// When using the Vectored Exception Handler, this is used to remove the VEH
// (unused when using SEH instead)
PVOID VEH_Handle = nullptr;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		// The DisableThreadLibraryCalls function lets a DLL disable the DLL_THREAD_ATTACH and DLL_THREAD_DETACH notification calls.
		//  This can be a useful optimization for multithreaded applications that have many DLLs, frequently createand delete threads,
		//  and whose DLLs do not need these thread - level notifications of attachment/detachment.
		DisableThreadLibraryCalls(hModule);

		if (!console.open())
		{
			// Indicate DLL loading failed
			return FALSE;
		}

		// Find the address of the true Function
		HMODULE h_module = GetModuleHandleA(module_name);
		if (h_module == NULL)
		{
			fprintf(console.stream, "Unable to retrieve handle for module %s\n", module_name);
			return FALSE;
		}
		func_addr = (DWORD)GetProcAddress(h_module, function_name);
		func_addr_offset = func_addr + 0x2; // jump over first instruction (instruction 'mov edi, edi' is 2 bytes long => view in Ghidra)

		// Search the main thread
		h_main_thread = getMainThread();
		if (h_main_thread == NULL)
		{
			fprintf(console.stream, "Unable to retrieve handle for main thread\n");
			return FALSE;
		}

		fprintf(console.stream, "Setting Exception Filter.\n");
		// Set the Exception Handler (choose SEH or VEH!)
		(void)SetUnhandledExceptionFilter(ExceptionFilter);
		// VEH_Handle = AddVectoredExceptionHandler(1, ExceptionFilter);

		// Set debug registers in thread context to trigger exception
		fprintf(console.stream, "Setting breakpoint in Dr registers.\n");

		thread_context.Dr0 = func_addr; // DR0 is set to the desired address (address of MessageBoxW)
		thread_context.Dr7 = (1 << 0);	// DR7 is set to a local enable level for the address in DR0

		SetThreadContext(h_main_thread, &thread_context);
		// Removing the breakpoints is as simple as clearing the debug registers in the main thread.

		// Test: also set for this thread and call function
		CreateThread(nullptr, NULL, testHook, hModule, NULL, nullptr);
	}

	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
	{
		fprintf(console.stream, "Uninstalling the hook ...\n");

		thread_context = {CONTEXT_DEBUG_REGISTERS};
		SetThreadContext(h_main_thread, &thread_context);

		// Remove the Exception Handler (choose SEH or VEH!)
		(void)SetUnhandledExceptionFilter(NULL);
		// RemoveVectoredExceptionHandler(VEH_Handle);

		CloseHandle(h_main_thread);

		// Open a MessageBox to allow reading the output
		MessageBoxW(NULL, L"Press Ok to close", L"Closing", NULL);
	}
	}
	return TRUE;
}
