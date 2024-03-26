# Dynamically Track Register Preservation Expectations Across Syscalls 

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.10372035.svg)](https://doi.org/10.5281/zenodo.10372035)

This Intel Pin tool tracks at run time whether any syscalls are executed between a consecutive read from and write to the same register. It was used to evaluate syscall ABI expectations of common applications for our DSN'24 paper "System Call Interposition Without Compromise". 

Intel Pin is a dynamic binary instrumentation (DBI) framework developed by Intel that enables creating custom analyses. More info at https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html. 

## Building

Make sure intel pin is downloaded somewhere. You can get the latest release here: https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html

Then run `make` from the project root and specify the location of your PIN installation. Example:
```bash
make PIN_ROOT=/home/you/intelpin/pin-3.28-98749-g6643ecee5-gcc-linux/
```

## Run Pintool

To run our Pin tool, execute the following: 

```bash
$PIN_ROOT/pin -t /path/tosyscall_register_clobbering/obj-intel64/syscallregdeps.so -- <program name>
```

## Output

The analysis output will be written to the `pinout` directory.
Each evaluated program has a corresponding `pinatrace_<coreutil>.out` file.

### Pinatrace Output

The `pinatrace_<coreutil>.out` file corresponding to each evaluated binary shows how many affected systemcalls.
For example: 

    1 affected syscalls out of 185 syscalls

### Log Output

For more information, there is a corresponding `log_<coreutil>.out` file for each affected binary, showing an instruction trace of each affected read in the binary.

For example, the relevant instructions that are generated when evaluating the coreutil cp are shown below with some annotations:

    ...
    0x7f587e811dce:    movq xmm0, r8
    0x7f587e811dd3:    push rbx
    0x7f092d499dd4:    punpcklqdq xmm0, xmm0                    <--- Last write to xmm0
    0x7f092d499dd8:    mov rdx, qword ptr fs:[0x10]
    0x7f092d499de1:    lea rdi, ptr [rdx+0x2d0]
    ...
    0x7f092d499e00:    xor eax, eax
    0x7f092d499e02:    mov eax, 0xda
    0x7f092d499e07:    syscall                                  <--- Syscall
    0x7f092d499e09:    mov dword ptr [rdx+0x2d0], eax
    0x7f092d499e0f:    lea rax, ptr [rdx+0x310]
    ...
    0x7f092d499e4d:    movups xmmword ptr [rdx+0x2d8], xmm1
    0x7f092d499e54:    syscall                                  <--- Syscall
    0x7f092d499e56:    mov rax, qword ptr [rip+0x17163]
    ...
    0x7f092d499e7e:    movups xmmword ptr [rdx+0x2c0], xmm0     <--- Transgressing read from xmm0

### Verify Transgressing Instructions

To find which library/source code the transgressing instructions originate from, you can attach gdb to the Pintool, the instructions to do so are found here: https://software.intel.com/sites/landingpage/pintool/docs/98579/Pin/doc/html/index.html#APPDEBUG_UNIX. The Pintool will recognize it when a gdb instance is attached to it and will insert a breakpoint at every transgressing systemcall.

However, if the program uses few libraries it may be simpler to run ldd and go through the linked system libraries, objdumping them one by one, to find the corresponding code.

    ldd /bin/ls

You can dissassemble the system libraries with, for example, objdump:

    objdump -M intel -d /path/to/program <name>.asm


To verify whether the registers were truly supposed to be preserved, they must hale from the same function without a function call in between, as these registers are not expected to be preserved across function calls.

Another common false positive arises when registers are preserved, for example, before a function call, as often all xmm or ymm registers will be preserved even when not all registers were used.