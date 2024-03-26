#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <ostream>
#include <set>
#include <sstream>
#include <types.h>
#include <unistd.h>
#include <utility>
#include <pin.H>
#include <stdio.h>
#include <map>
#include <vector>
#include <linux/unistd.h>
#include <string>
#include <array>
#include <sys/stat.h>



#define ABCD_VERSIONS(regletter) \
    REG_R##regletter##X,        \
    REG_E##regletter##X,        \
    REG_##regletter##X,         \
    REG_##regletter##L,         \
    REG_##regletter##H,

FILE* trace;

std::string name_analysed_process;

// class thread_data_t {
//     public:
//         thread_data_t(): _count(0) {}
//         UINT64 _count;
//         UINT8 _pad[_PADSIZE];
// };

// static TLS_KEY tls_key = INVALID_TLS_KEY;

struct ins_reg{
    std::string ins_dis;
    REG reg;
    int sys;
    uintptr_t sys_addr;
};

inline bool operator<(const ins_reg &lhs, const ins_reg &rhs)
{
    return strcmp(lhs.ins_dis.c_str(), rhs.ins_dis.c_str()) || lhs.reg < rhs.reg || lhs.sys_addr != rhs.sys_addr;
}
REG r10[] = {
    REG_R10,
    REG_R10B,
    REG_R10D,
    REG_R10W,
};

//R10 not saved

std::set<REG> zpoline = {
    REG_RDI,
    REG_EDI,
    REG_DI,
    REG_DIL,

    REG_RSI,
    REG_ESI,
    REG_SI,
    REG_SIL,

    REG_RDX,
    REG_EDX,
    REG_DX,
    REG_DH,
    REG_DL,

    REG_RCX,
    REG_ECX,
    REG_CX,
    REG_CH,
    REG_CL,

    REG_R8,
    REG_R8B,
    REG_R8D,
    REG_R8W,

    REG_R9,
    REG_R9B,
    REG_R9D,
    REG_R9W,

    REG_R11,
    REG_R11B,
    REG_R11D,
    REG_R11W,

    // c calling convention
    REG_RBX,
    REG_EBX,
    REG_BX,
    REG_BH,
    REG_BL,

    REG_RSP,
    REG_ESP,
    REG_SP,
    REG_SPL,

    REG_RBP,
    REG_EBP,
    REG_BP,
    REG_BPL,

    REG_R12,
    REG_R12B,
    REG_R12D,
    REG_R12W,

    REG_R13,
    REG_R13B,
    REG_R13D,
    REG_R13W,

    REG_R14,
    REG_R14B,
    REG_R14D,
    REG_R14W,

    REG_R15,
    REG_R15B,
    REG_R15D,
    REG_R15W,

    REG_R10,
    REG_R10B,
    REG_R10D,
    REG_R10W,
    
    REG_MXCSR,
};

std::set<UINT64> reg_written;
std::set<REG> problem_reg;
std::set<ins_reg> problem_reg_with_ins;
bool syscall_happened;
int last_sys;
uintptr_t last_sys_addr;
uint sys_count = 0;
std::set<uint> problematic_sysalls;

struct RecentInstruction {
    void* ip = nullptr;
    char* disas_string = nullptr;

    bool is_empty() { return ip == nullptr; }
};

struct RecentInstructionsBuffer {
    std::array<RecentInstruction, 128> buffer;
    uint tip_idx = 0;

    void push(char* disas, void* ip) {
        buffer[tip_idx] = {ip, disas};
        tip_idx++;
        tip_idx %= buffer.size();
    }

    void log() {
        std::stringstream file_name;
        file_name << "pinout/log_" << name_analysed_process << ".out";
        FILE* log = fopen(file_name.str().c_str(),"a");
        // iterate forwards in wrap-around fashion
        // start with oldest
        //LOG("Issue:\n");
        fprintf(log, "Issue:\n");
        for (uint i = 1; i < buffer.size(); i++) {
            auto idx = (tip_idx+i) % buffer.size();
            auto inst = buffer.at(idx);
            if (!inst.is_empty()) {
                std::stringstream out;
                out << inst.ip << ":    " << inst.disas_string << "\n";
                //LOG(out.str());
                fprintf(log, "%s", out.str().c_str());
                fflush(log);
            }
        }
    }
};

RecentInstructionsBuffer recent_insts;

// need syscall entry cause need to make exception for sigreturn
VOID syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
    assert(SYSCALL_STANDARD_IA32E_LINUX == std);
    sys_count ++;
    syscall_happened = true;
    if (PIN_GetSyscallNumber(ctx, std) == __NR_rt_sigreturn) {
        syscall_happened = false;
    }
    last_sys = PIN_GetSyscallNumber(ctx, std);
    last_sys_addr = PIN_GetContextReg(ctx, REG_RIP);
    
    reg_written.clear();
    reg_written.insert(REG_RAX);
    reg_written.insert(REG_EAX);
    reg_written.insert(REG_AX);
    reg_written.insert(REG_AH);
    reg_written.insert(REG_AL);
    // fill in rest C
    reg_written.insert(REG_RCX);
    reg_written.insert(REG_ECX);
    reg_written.insert(REG_CX);
    reg_written.insert(REG_CH);
    reg_written.insert(REG_CL);
    
    reg_written.insert(REG_SEG_FS);
    reg_written.insert(REG_RIP);

    
    //GAX, RAX, REG_ORIG_RAX, EAX, AX,AL,AH
    //
    //
}

bool read_value_matters(INS ins) {
    if (strcmp(INS_Mnemonic(ins).c_str(), "VPXOR") == 0 && INS_RegR(ins, 0) == INS_RegR(ins, 1) && INS_RegWContain(ins, INS_RegR(ins, 0))) {
        return false;
    }
    if ((strcmp(INS_Mnemonic(ins).c_str(), "PXOR") == 0 ||
        strcmp(INS_Mnemonic(ins).c_str(), "XOR") == 0) &&
        INS_RegWContain(ins, INS_RegR(ins, 0))){
        return false;
    }
    return true;
}

static ADDRINT regInst(UINT64 reg, char* ins, void* ins_addr) {
    if(syscall_happened) {
        if(!reg_written.count(reg)){
            problematic_sysalls.insert(last_sys);
            recent_insts.log();
            // fprintf(trace, "%s: %p    %s\n", REG_StringShort(static_cast<REG>(reg)).c_str(), ins_addr, ins);
            problem_reg_with_ins.insert({std::string(ins), static_cast<REG>(reg), last_sys, last_sys_addr});
            return 1;
        }
    }
    return 0;
}

static VOID write_enc(UINT64 reg) {
    reg_written.insert(reg);
}

static VOID DoBreakpoint(const CONTEXT *ctxt, THREADID tid, UINT64 reg, char* ins)
{
    //ConnectDebugger();
    if (PIN_GetDebugStatus() == DEBUG_STATUS_UNCONNECTED)
        return;
    
    std::ostringstream info;
    info << "Hello: last syscall " << last_sys << " at " << std::hex <<  last_sys_addr << " current reg " << REG_StringShort(static_cast<REG>(reg)) << " inst: " << ins;
    //tinfo->_os << "Thread " << std::dec << tid << " last syscall " << last_sys << " at " << last_sys_addr;
    PIN_ApplicationBreakpoint(ctxt, tid, FALSE, info.str());
}


#define XMM_TO_YMM(regnum) \
    case REG_XMM##regnum: return REG_YMM##regnum;

#define XMM_TO_YMM_CASES \
    XMM_TO_YMM(0)\
    XMM_TO_YMM(1)\
    XMM_TO_YMM(2)\
    XMM_TO_YMM(3)\
    XMM_TO_YMM(4)\
    XMM_TO_YMM(5)\
    XMM_TO_YMM(6)\
    XMM_TO_YMM(7)\
    XMM_TO_YMM(8)\
    XMM_TO_YMM(9)\
    XMM_TO_YMM(10)\
    XMM_TO_YMM(11)\
    XMM_TO_YMM(12)\
    XMM_TO_YMM(13)\
    XMM_TO_YMM(14)\
    XMM_TO_YMM(15)

static REG xmm_to_ymm(REG xmm) {
    switch (xmm) {
        XMM_TO_YMM_CASES
        default:
            assert(!"unreachable");
    }
}

#define YMM_TO_XMM(regnum) \
    case REG_YMM##regnum: return REG_XMM##regnum;

#define YMM_TO_XMM_CASES \
    YMM_TO_XMM(0)\
    YMM_TO_XMM(1)\
    YMM_TO_XMM(2)\
    YMM_TO_XMM(3)\
    YMM_TO_XMM(4)\
    YMM_TO_XMM(5)\
    YMM_TO_XMM(6)\
    YMM_TO_XMM(7)\
    YMM_TO_XMM(8)\
    YMM_TO_XMM(9)\
    YMM_TO_XMM(10)\
    YMM_TO_XMM(11)\
    YMM_TO_XMM(12)\
    YMM_TO_XMM(13)\
    YMM_TO_XMM(14)\
    YMM_TO_XMM(15)

static REG ymm_to_xmm(REG ymm) {
    switch (ymm) {
        YMM_TO_XMM_CASES
        default:
            assert(!"unreachable");
    }
}



VOID print_ins(char* ins, void* ins_ptr) {
    recent_insts.push(ins, ins_ptr);
}

VOID instruction_callback(INS ins, VOID* v) {
    IPOINT where = IPOINT_AFTER;
    if (!INS_IsValidForIpointAfter(ins))
        where = IPOINT_TAKEN_BRANCH;
    auto disas = INS_Disassemble(ins);
    auto c_str = strdup(disas.c_str());
    INS_InsertCall(ins, IPOINT_BEFORE , (AFUNPTR)print_ins, IARG_PTR, c_str, IARG_INST_PTR, IARG_END);
    for(uint i = 0; i < INS_MaxNumRRegs(ins); i++) {
        REG reg = INS_RegR(ins, i);
        if (!zpoline.count(reg)){
            if(read_value_matters(ins)){
                INS_InsertIfCall(ins, where , (AFUNPTR)regInst, IARG_UINT64, static_cast<UINT64>(reg), IARG_PTR, c_str, IARG_INST_PTR, IARG_END);
                INS_InsertThenCall(ins, where, (AFUNPTR)DoBreakpoint, IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_UINT64, reg, IARG_PTR, c_str, IARG_END);
            }
        }
    }
    for(uint i = 0; i < INS_MaxNumWRegs(ins); i++){
        REG reg = INS_RegW(ins, i);
        if(REG_is_xmm(reg)){
            if(INS_Mnemonic(ins).at(0) == 'V' && INS_Mnemonic(ins)!= "VERR" && INS_Mnemonic(ins) != "VERW"){
                auto ymm = xmm_to_ymm(reg);
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)write_enc, IARG_UINT64, static_cast<UINT64>(ymm), IARG_END);
            }
        }
        if(REG_is_ymm(reg)){
            auto xmm = ymm_to_xmm(reg);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)write_enc, IARG_UINT64, static_cast<UINT64>(xmm), IARG_END);
        }
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)write_enc, IARG_UINT64, static_cast<UINT64>(reg), IARG_END);
    }
}

// VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
// {
//     //numThreads++;
//     thread_data_t* tdata = new thread_data_t;
//     if (PIN_SetThreadData(tls_key, tdata, threadid) == FALSE)
//     {
//         cerr << "PIN_SetThreadData failed" << endl;
//         PIN_ExitProcess(1);
//     }
// }

BOOL FollowChild(CHILD_PROCESS cProcess, VOID* userData)
{
    fprintf(trace, "before child:%u\n", getpid());
    INT argc;
    const CHAR *const * arg_buf = NULL;
    CHILD_PROCESS_GetCommandLine(cProcess, &argc, &arg_buf);
    auto command = arg_buf[0];
    printf("command = %s\n", command);
    if (strcmp(command, "/usr/lib/git-core/git-submodule") /*|| strcmp(command, "git") */ ){
        printf("caught a git\n");
        return FALSE;
    }
    return TRUE;
}

VOID end(INT32 code, VOID *v){
    fprintf(trace, "%ld affected syscalls out of %d syscalls", problematic_sysalls.size(), sys_count);
    fprintf(trace, "\n\n--------------------------------\n\n");
    for (auto& r : problem_reg_with_ins){
        fprintf(trace, "%s in:\n    %s\n    sys: %d, %p\n",  
            REG_StringShort(r.reg).c_str(), r.ins_dis.c_str(), r.sys, (void*)r.sys_addr);
        
    }
    // if (problematic_sysalls.size() == 0) {
    //     std::stringstream file_name;
    //     file_name << "pinout/pinatrace" << getpid() << ".out";
    //     remove(file_name.str().c_str());
    // }
}

int main(int argc, char* argv[]) {
    if (PIN_Init(argc, argv)) {
        assert(!"IDK, you wrong");
    }
    printf("starting pintool\n");
    struct stat st = {0};
    if(stat("pinout", &st) == -1) {
        mkdir("pinout", 0700);
    }
    std::stringstream file_name;

    char* temp = strtok(argv[6], "/");
    while (temp != NULL) {
        name_analysed_process = temp;
        temp = strtok(NULL, "/");
    }
    printf("\n%s\n", name_analysed_process.c_str());
    file_name << "pinout/pinatrace_" << name_analysed_process << ".out";
    trace = fopen(file_name.str().c_str(), "w");
    syscall_happened = false;

    // PIN_AddThreadStartFunction(ThreadStart, NULL);

    PIN_AddFollowChildProcessFunction(FollowChild, NULL);
    PIN_AddSyscallEntryFunction(syscall_entry, NULL);

    INS_AddInstrumentFunction(instruction_callback, NULL);

    PIN_AddFiniFunction(end, NULL);
    PIN_StartProgram();    
}

