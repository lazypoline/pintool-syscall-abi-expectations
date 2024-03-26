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

## Expected Output

The analysis output will be written to the `pinout` directory.
You should find a `pinatrace_<coreutil>.out` file for each evaluated program.

### Pinatrace Output

The `pinatrace_<coreutil>.out` file corresponding to each evaluated binary shows how many affected systemcalls.
For example: 

    1 affected syscalls out of 185 syscalls

You should find the results summarized in Table III under "Ubuntu 20.04" in the paper.

Below you can see which read of a register is affected along with the affecting syscall. You should find that the affected register is `xmm0` as shown in Listing 1.

### Log Output

For more information, there is a corresponding `log_<coreutil>.out` file for each affected binary, showing an instruction trace of each affected read in the binary.

If you look at the 4 generated log files, you will find that all 4 issues are the same and correspond with Listing 1, as described in the subsection *Microbenchmarks* of the Evaluation Section:

    "In Ubuntu 20.04, 40% of the evaluated coreutils are affected by the same pthread initialization issue, 
    which we described in Listing 1."

For example, the relevant instructions in log_cp.out, also present in Listing 1, are shown below:

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

### Origin Transgressing Instructions

To find where which library these instructions come from, you can attach gdb to the Pintool if you follow the instructions found here:

https://software.intel.com/sites/landingpage/pintool/docs/98579/Pin/doc/html/index.html#APPDEBUG_UNIX

However, it is simpler to simply run ldd and go through the linked system libraries, objdumping them one by one, to find the corresponding code.

    ldd /bin/ls

Dissassemble the system libraries with the following command

    objdump -M intel -d /usr/lib/x86_64-linux-gnu/<system_lib> > <system_lib>.asm

Search the generated assembly files for the transgressing read instruction:

    movups XMMWORD PTR [rdx+0x2c0],xmm0

This instruction belongs to `libpthread.so.0`. The instruction is part of the function `__pthread_initialize_minimal`. Like found in the paper in the Implementation Section in subsection *ABI Compatibility*: 
    "Listing 1 presents a representative example, 
    taken from the pthread initialization routine of glibc 2.31."

To verify that the last read from and last write to xmm0 are part of the same function, meaning xmm0 is truly expected to be preserved, search for the last write to xmm0 (the instruction below). You will find that this instruction is also part of `__pthread_initialize_minimal`.

    punpcklqdq xmm0,xmm0

If you are curious, using bootlin you can find the source code of `__pthread_initialize_minimal`. 
