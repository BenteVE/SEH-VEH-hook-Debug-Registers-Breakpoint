/*
    SOURCES: 
        - https://www.codereversing.com/blog/archives/76
    PROJECT SETTINGS: 

    INFO:
        - USAGE: 
            This code creates a DLL. When the DLL is injected in an application it will install an SEH hook on the 
            MessageBoxW function to change the text in the textbox.

        - Different ways to create SEH/VEH hooks
            There are several ways to trigger an exception that will be caught by our Exception handler:
                - STATUS_GUARD_PAGE_VIOLATION
                - STATUS_ACCESS_VIOLATION (with NO_ACCESS flag)
                - EXCEPTION BREAKPOINT (INT3 opcode)
                - setting Dr registers in PCONTEXT

            When we return to the place of the exception after executing our hook, we have to make sure the exception is not triggered again.
            There are 2 ways to accomplish this:
                - SINGLE STEP EXCEPTION
                - creating a trampoline with assembly

            There are also different ways to install an exception handler
                - by using SetUnhandledExceptionFilter/SetVectoredExceptionHandler
                - by changing pointers in Thead Information Block (TIB) with assembly
                  (https://www.mpgh.net/forum/showthread.php?t=291797)
                  (http://www.rohitab.com/discuss/topic/36211-c-hooking-functions-with-breakpoints-and-seh/)

            In this program we will use the Dr registers in combination with an assembly trampoline to trigger and recover from the exception,
            and we will use SetUnhandledExceptionFilter to install the handler

        - SEH: 
            Structured Exception Handlers (SEHs) in Windows are stored as a linked list.
            When an exception is raised, this list is traversed until a handler for the exception is found.
            If one is found then the handler gains execution of the program and handles the exception.
            If one is not found then the application goes into an undefined state and may crash depending on the type of exception.

        - HARDWARE BREAKPOINTS: 
            To use hardware breakpoints there are eight debug registers (DR0 to DR7) that can be utilized. 
            Eight, however, is a bit of an overstatement — DR4 and DR5 are no longer used and their functionality is 
            replaced with DR6 and DR7, so there are really six. The debug registers DR0 – DR3 can each hold a linear 
            address to break on depending on how the debug control (DR7) register is set. The debug status (DR6) 
            register lets a debugger determine which debug conditions have occurred. 
            Therefore, you are permitted four addresses to set hardware breakpoints on 
            (assuming that they’re not being chained across threads).   
            Removing the breakpoints is as simple as clearing the debug registers in the main thread.

        - BUILDING
            Because of the assembly code, this can only be compiled for x86
*/

#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

DWORD func_addr = NULL;
DWORD func_addr_offset = NULL;

// To find parameters of the function you are replacing, you can use Ghidra.
void modify_text(PCONTEXT debug_context) {
    DWORD oldProtection{};
    VirtualProtect((LPVOID)(debug_context), 0x1000, PAGE_READWRITE, &oldProtection);
    printf("Changed Protection");

    //TODO: debug this, changes in stack causes crash
    //char* text = (char*)(*(DWORD*)(debug_context->Esp + 0x8));
    //int length = strlen(text);
    //_snprintf(text, length, "REPLACED");

    printf("Replaced text");
    VirtualProtect((LPVOID)(debug_context), 0x1000, oldProtection, &oldProtection);
    printf("Changed Protection");
}

// This stub function contains the first instruction of the function that has the breakpoint on it. 
// Then it jumps one byte past the breakpoint address, where the next instruction starts. 
// This is needed because if EIP is not modified, the exception will be raised again once the handler finishes and an infinite loop will occur.
// To find the first instruction of the function you are replacing, you can use Ghidra. 
// Make sure you analyze the correct DLL (32-bit in SysWOW64 folder or 64-bit in System32 folder).
void __declspec(naked) MessageBoxW_trampoline(void) {
    printf("before trampoline\n");
    __asm {
        mov edi, edi
        jmp[func_addr_offset]
    }
    printf("after trampoline\n");
}

// print parameters to console 
void print_parameters(PCONTEXT debug_context) {
    printf("EAX: %X EBX: %X ECX: %X EDX: %X\n",
        debug_context->Eax, debug_context->Ebx, debug_context->Ecx, debug_context->Edx);
    printf("ESP: %X EBP: %X\n",
        debug_context->Esp, debug_context->Ebp);
    printf("ESI: %X EDI: %X\n",
        debug_context->Esi, debug_context->Edi);

    printf("Parameters\n"
        "HWND: %p\n"
        "lptext: %s\n"
        "lpcaption: %s\n"
        "type: %X\n",
        (HWND)(*(PDWORD)(debug_context->Esp + 0x4)), //ESP is stack pointer, all parameters are on the stack
        (char*)(*(PDWORD)(debug_context->Esp + 0x8)),
        (char*)(*(PDWORD)(debug_context->Esp + 0xC)), //prints first char of the parameter (Why only first character?)
        (UINT)(*(PDWORD)(debug_context->Esp + 0x10))); //prints 23h == MB_ICONQUESTION + MB_YESNOCANCEL

}

// When an exception is raised, ExceptionFilter checks to see whether the exception occurred at the desired address.
// If so, the exception is handled and now the context record 
// (containing, among other things, the values of all registers and flags when the breakpoint was hit).
// Since the function sets up a standard BP - based frame, the parameters can all be retrieved through 
// ESP(since the stack frame was not set up yet when the breakpoint was hit). 
// All registers and parameters can then be inspected and/or modified as shown in print_parameters and modify_text.
LONG WINAPI ExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if ((DWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress == func_addr) {
            PCONTEXT debug_context = ExceptionInfo->ContextRecord;
            printf("Breakpoint hit!\n");
            print_parameters(debug_context);
            
            printf("Modifying parameters on stack (not implemented).\n");
            //modify parameters on stack
            //modify_text(debug_context);

            printf("Using trampoline to go to instruction after breakpoint.\n");
            debug_context->Eip = (DWORD)&MessageBoxW_trampoline; //PAGE FAULT bij executing trampoline (op wine)
            //VirtualProtect() => proberen oplossen op Wine

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

#include <fstream>
DWORD WINAPI installSEHHook(PVOID base) {
    HMODULE modUser32 = GetModuleHandle(TEXT("user32.dll"));
    func_addr = (DWORD)GetProcAddress(modUser32, "MessageBoxW");
    func_addr_offset = func_addr + 0x2; // jump over first instruction (instruction 'mov edi, edi' is 2 bytes long => view in Ghidra)

    // Use TH32Snapshot to iterate all threads on the system untill we find the threads of the target proces. 
    // We then select the oldest (main) thread of this process.
    // The handle for this thread is kept so the debug registers can be set up. 
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
            do {
                if (thread_entry32.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(thread_entry32.th32OwnerProcessID)
                    && thread_entry32.th32OwnerProcessID == GetCurrentProcessId()
                    && thread_entry32.th32ThreadID != GetCurrentThreadId()) {
                    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                        FALSE, thread_entry32.th32ThreadID);
                    GetThreadTimes(hThread, &creation_time, &exit_time, &kernel_time, &user_time);
                    if (CompareFileTime(&creation_time, &prev_creation_time) == -1) {
                        memcpy(&prev_creation_time, &creation_time, sizeof(FILETIME));
                        if (hMainThread != NULL)
                            CloseHandle(hMainThread);
                        hMainThread = hThread;
                        printf("Main thread found!\n");
                    }
                    else
                        CloseHandle(hThread);
                }
                thread_entry32.dwSize = sizeof(THREADENTRY32);
            } while (Thread32Next(hTool32, &thread_entry32));

            printf("Setting Exception Filter.\n");
            (void)SetUnhandledExceptionFilter(ExceptionFilter);
            
            printf("Setting breakpoint in Dr registers.\n");
            CONTEXT thread_context = { CONTEXT_DEBUG_REGISTERS }; //CONTEXT structure is set up with ContextFlags being CONTEXT_DEBUG_REGISTERS
            thread_context.Dr0 = func_addr; // DR0 is set to the desired address (address of MessageBoxW)
            thread_context.Dr7 = (1 << 0); // DR7 is set to a global enable level for the address in DR0
            SetThreadContext(hMainThread, &thread_context);

            //As test: also set for this thread and call function
            printf("Test: calling MessageBox.\n");
            SetThreadContext(GetCurrentThread(), &thread_context);
            MessageBoxW(NULL, L"Finished", L"MyMessageBox", MB_OK);

            CloseHandle(hMainThread);
        }
        CloseHandle(hTool32);
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    FILE* stream; //An out parameter that will point to the reopened stream when the function returns.
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        //The DisableThreadLibraryCalls function lets a DLL disable the DLL_THREAD_ATTACH and DLL_THREAD_DETACH notification calls.
        // This can be a useful optimization for multithreaded applications that have many DLLs, frequently createand delete threads, 
        // and whose DLLs do not need these thread - level notifications of attachment/detachment.
        DisableThreadLibraryCalls(hModule);

        // Open console for debugging
        if (AllocConsole()) {
            freopen_s(&stream, "CONOUT$", "w", stdout);
            SetConsoleTitle(L"Console");
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            printf("DLL loaded.\n");
        }

        // install SEH hook
        CreateThread(nullptr, NULL, installSEHHook, hModule, NULL, nullptr); break;
    
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

