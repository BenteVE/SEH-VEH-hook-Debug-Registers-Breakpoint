# SEH/VEH hooking using Debug Registers

A Structured or Vectored Exception Handler (SEH/VEH) hook

## Exception Handling

### Structured Exception Handler

Structured Exception Handlers (SEHs) in Windows are stored as a linked list.
When an exception is raised, this list is traversed until a handler for the exception is found.
If one is found then the handler gains execution of the program and handles the exception.
If one is not found then the application goes into an undefined state and may crash depending on the type of exception.

### Vectored Exception Handler

## Installing the hook

### Creating an exception

- STATUS_GUARD_PAGE_VIOLATION
- STATUS_ACCESS_VIOLATION (with NO_ACCESS flag)
- EXCEPTION BREAKPOINT (INT3 opcode)
- setting Dr registers in PCONTEXT

### Recovering from the exception

When we return to the place of the exception after executing our hook, we have to make sure the exception is not triggered again.

- SINGLE STEP EXCEPTION
- creating a trampoline with assembly instructions

### Installing the ExceptionFilter

- by using SetUnhandledExceptionFilter/SetVectoredExceptionHandler
- by changing pointers in Thead Information Block (TIB) with assembly

## Example

In this example we will use the Dr registers in combination with an assembly trampoline to trigger and recover from the exception, and we will use SetUnhandledExceptionFilter to install the handler.
