/*
 * @Date: 2021-12-06 21:52:44
 * @LastEditors: zx Zhou
 * @LastEditTime: 2022-03-29 17:45:01
 * @FilePath: /libdft64/tools/cmp_hook.cpp
 */

#include "cmp_hook.h"

//#define __DEBUG__
#define OUTPUT_PATH "./scripts/info/cmp_hook.info"

std::map<ADDRINT, FSFG> fzstate;
std::ofstream out;

tag_t tagmap_get_mem_len(ADDRINT addr, unsigned int n, size_t &tag_len) {
    tag_t ts = tag_traits<tag_t>::cleared_val;
    tag_len = 0;
    for (size_t i = 0; i < n; i++) {
        const tag_t t = tagmap_getb(addr + i);
        if (tag_is_empty(t))
            continue;
        tag_len ++;
        ts = tag_combine(ts, t);
    }
    return ts;
}

tag_t tagmap_get_reg_len(THREADID tid, unsigned int reg_idx, size_t n, size_t &tag_len) {
    tag_t ts = tag_traits<tag_t>::cleared_val;
    tag_len = 0;
    for (size_t i = 0; i < n; i++) {
        const tag_t t = tagmap_getb_reg(tid, reg_idx, i);
        if (tag_is_empty(t))
            continue;
        tag_len++;
        ts = tag_combine(ts, t);
    }
    return ts;
    }

// strcmp: sub eax, ecx
//         jne loc
// one-byte cmp: cmp al, 0x68
//               jne loc

const char* cmp_functions[CMPFUNCNUM] = {"strcmp", "memcmp", "strncmp", "strrchr"};

VOID strcmp_hook(const char* s1, const char* s2, size_t ret_addr){
    if (ret_addr > 0x7fffffffffff) {
      return;
    }
    tag_t tag0, tag1;
    size_t tagl0, tagl1;
    size_t len0 = strlen(s1), len1 = strlen(s2);
    // tag_t t1 = tagmap_getn((ADDRINT)s1, len1);
    // tag_t t2 = tagmap_getn((ADDRINT)s2, len2);
    tag0 = tagmap_get_mem_len((ADDRINT)s1, len0, tagl0);
    tag1 = tagmap_get_mem_len((ADDRINT)s2, len1, tagl1);
    size_t cmp_len = max(tagl0, tagl1);
    if (cmp_len){
        if (fzstate.find(ret_addr) != fzstate.end()){
            fzstate[ret_addr].update_tag(tag_combine(tag0, tag1));
        }
        else{
            fzstate[ret_addr] = FSFG(cmp_len, tag_combine(tag0, tag1), ret_addr);
        }
    }
}

VOID memcmp_hook(const void * ptr1, const void * ptr2, size_t num, size_t ret_addr){
    if (ret_addr > 0x7fffffffffff) {
      return;
    }
    tag_t tag0, tag1;
    size_t tagl0, tagl1;
    tag0 = tagmap_get_mem_len((ADDRINT)ptr1, num, tagl0);
    tag1 = tagmap_get_mem_len((ADDRINT)ptr2, num, tagl1);
    size_t cmp_len = max(tagl0, tagl1);
    if (cmp_len){
        if (fzstate.find(ret_addr) != fzstate.end()){
            fzstate[ret_addr].update_tag(tag_combine(tag0, tag1));
        }
        else{
            fzstate[ret_addr] = FSFG(cmp_len, tag_combine(tag0, tag1), ret_addr);
        }
    }
}

VOID strncmp_hook(const char * ptr1, const char * ptr2, size_t num, size_t ret_addr){
    if (ret_addr > 0x7fffffffffff) {
      return;
    }
    tag_t tag0, tag1;
    size_t tagl0, tagl1;
    tag0 = tagmap_get_mem_len((ADDRINT)ptr1, num, tagl0);
    tag1 = tagmap_get_mem_len((ADDRINT)ptr2, num, tagl1);
    size_t cmp_len = max(tagl0, tagl1);
    if (cmp_len){
        if (fzstate.find(ret_addr) != fzstate.end()){
            fzstate[ret_addr].update_tag(tag_combine(tag0, tag1));
        }
        else{
            fzstate[ret_addr] = FSFG(cmp_len, tag_combine(tag0, tag1), ret_addr);
        }
    }   
}

VOID strrchr_hook( const char * str, int character, size_t ret_addr ){
    if (ret_addr > 0x7fffffffffff) {
      return;
    }
    size_t cmp_len = 0;
    tag_t tag0, tag1;
    size_t tagl0, tagl1;
    size_t len0 = strlen(str);
    tag0 = tagmap_get_mem_len((ADDRINT)str, len0, tagl0);
    tag1 = tagmap_get_mem_len((ADDRINT)character, 1, tagl1);
    if (tagl1 != 0){
      cmp_len = tagl1;
    }
    else{
      cmp_len = max(tagl0, tagl1);
    }
    if (cmp_len){
        if (fzstate.find(ret_addr) != fzstate.end()){
            fzstate[ret_addr].update_tag(tag_combine(tag0, tag1));
        }
        else{
            fzstate[ret_addr] = FSFG(cmp_len, tag_combine(tag0, tag1), ret_addr);
        }
    }  
}

/*
strcoll relies on strcmp
*/
// VOID strcoll_hook( const char * str1, const char * str2 );

VOID CmpFuncTrace(IMG img, VOID *v)
{
    // Instrument the malloc() and free() functions.  Print the input argument
    // of each malloc() or free(), and the return value of malloc().
    for (unsigned int cmp_func_idx = 0; cmp_func_idx < CMPFUNCNUM; cmp_func_idx ++){
        RTN rtn = RTN_FindByName(img, cmp_functions[cmp_func_idx]);  //  Find comparison functions
        if (RTN_Valid(rtn)){
            printf("%s\n", RTN_Name(rtn).c_str());

            RTN_Open(rtn);
            switch (cmp_func_idx){
              case 0:
                  RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcmp_hook,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_RETURN_IP,
                                IARG_END);
                  break;
              case 1:
                  RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memcmp_hook,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_RETURN_IP,
                                IARG_END);
                  break;
              case 2:
                  RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strncmp_hook,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_RETURN_IP,
                                IARG_END);
                  break;
              case 3:
                  RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strrchr_hook,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_RETURN_IP,
                                IARG_END);
                  break;
              default:
                  break;
            }	
            RTN_Close(rtn);
        }
    }
}

int cnt =0;

// Multiple defs to reduce instrument size

VOID memory_taint_check_mvi(ADDRINT mem_addr, size_t num, ADDRINT ret_addr)
{
    //printf("addr:%lx\n", mem_addr);
    size_t tagl=0;
    tag_t tag;
    if (mem_addr)
        tag = tagmap_get_mem_len((ADDRINT)mem_addr, num, tagl);
    if (tagl){
        if (fzstate.find(ret_addr) != fzstate.end()){
            fzstate[ret_addr].update_tag(tag);
        }
        else{
            fzstate[ret_addr] = FSFG(tagl, tag, ret_addr);
        }
    }

}

VOID memory_taint_check_mvm(ADDRINT mem_addr0, ADDRINT mem_addr1, size_t num0, size_t num1, ADDRINT ret_addr)
{
    //printf("addr1:%lx, addr2:%lx\n", mem_addr0, mem_addr1);
    size_t tagl0=0, tagl1=0;
    tag_t tag0, tag1;
    if (mem_addr0)
        tag0 = tagmap_get_mem_len((ADDRINT)mem_addr0, num0, tagl0);
    if (mem_addr1)
        tag1 = tagmap_get_mem_len((ADDRINT)mem_addr1, num1, tagl1);
    size_t cmp_len =max(tagl0, tagl1); 
    if (cmp_len){
        if (fzstate.find(ret_addr) != fzstate.end()){
            fzstate[ret_addr].update_tag(tag_combine(tag0, tag1));
        }
        else{
            fzstate[ret_addr] = FSFG(cmp_len, tag_combine(tag0, tag1), ret_addr);
        }
    }
}

VOID reg_taint_check(THREADID tid, unsigned int reg_idx, size_t n, size_t ret_addr)
{
    tag_t tag;
    size_t tagl;
    tag = tagmap_get_reg_len(tid, reg_idx, n, tagl);
    if (tagl)
    {
        if (fzstate.find(ret_addr) != fzstate.end()){
            fzstate[ret_addr].update_tag(tag);
        }
        else{
            fzstate[ret_addr] = FSFG(tagl, tag, ret_addr);
        }
    }
}

VOID DirectCmpHook(TRACE trace, VOID *v)
{
    // TODO: add an option for user-specified output filename
    out.open(OUTPUT_PATH, std::ios::app);
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)){
        // Output the fuzzing state flow graph for a bbl
        if (out.is_open()){
            for(std::map<ADDRINT, FSFG>::iterator it = fzstate.begin(); it != fzstate.end(); it++){
                out<<std::hex<<it->first<<":"<<it->second<<std::endl;
            }
        }
        fzstate.clear();

        INS tail_ins = BBL_InsTail(bbl);
        if (INS_Valid(tail_ins) && INS_IsBranch(tail_ins)){    
            INS branch_set_ins = INS_Prev(tail_ins);
            if (INS_IsOriginal(branch_set_ins)){
                int cat = INS_Category(branch_set_ins);
                // sub && cmp
                if (cat == 14){
                    //printf("[++] %d\n", cnt ++);
                    // enumerate different situations
                    //printf("[dis] %s : [cate] %d\n", INS_Disassemble(branch_set_ins).c_str(), cat);

                    // extract registers if there are 
                    REG reg0=REG_INVALID_, reg1=REG_INVALID_;
                    if (INS_OperandIsReg(branch_set_ins, 0)){
                        reg0 = INS_OperandReg(branch_set_ins, 0);
                        //printf("reg[0] %s %d\n", REG_StringShort(reg0).c_str(), reg0);   
                    }

                    if (INS_OperandIsReg(branch_set_ins, 1)){
                        reg1 = INS_OperandReg(branch_set_ins, 1);
                        //printf("reg[1] %s %d\n", REG_StringShort(reg1).c_str(), reg1); 
                    }

                    if (REG_valid(reg0)){   
                        INS_InsertCall(branch_set_ins, IPOINT_BEFORE, (AFUNPTR)reg_taint_check,
                            IARG_THREAD_ID,
                            IARG_UINT32, (unsigned int)reg0,
                            IARG_UINT32, DEFAULT_MEM_READ_SIZE,
                            IARG_INST_PTR,
                            IARG_END);
                    }

                    if (REG_valid(reg1)){   
                        INS_InsertCall(branch_set_ins, IPOINT_BEFORE, (AFUNPTR)reg_taint_check,
                            IARG_THREAD_ID,
                            IARG_UINT32, (unsigned int)reg1,
                            IARG_UINT32, DEFAULT_MEM_READ_SIZE,
                            IARG_INST_PTR,
                            IARG_END);
                    }
                    
                    if (!INS_IsMemoryRead(branch_set_ins)){
                        // No need for memory checking
                        continue;
                    }
                    
                    if (INS_OperandIsMemory(branch_set_ins, 0)){
                        if(INS_OperandIsMemory(branch_set_ins, 1)){
                            // cmp [mem1], [mem2]
                            size_t num0, num1;
                            if (INS_HasScatteredMemoryAccess(branch_set_ins))
                                num0 = INS_MemoryOperandSize(branch_set_ins, 0); 
                            else num0 = DEFAULT_MEM_READ_SIZE; 
                            
                            if (INS_HasScatteredMemoryAccess(branch_set_ins))
                                num1 = INS_MemoryOperandSize(branch_set_ins, 1);
                            else num1 = DEFAULT_MEM_READ_SIZE; 
                            
                            INS_InsertCall(branch_set_ins, IPOINT_BEFORE, (AFUNPTR)memory_taint_check_mvm,
                                IARG_MEMORYREAD_EA,
                                IARG_MEMORYREAD2_EA,
                                IARG_UINT32, num0,
                                IARG_UINT32, num1, 
                                IARG_INST_PTR,
                                IARG_END);
                            continue;
                        }
                        else{
                            // cmp [mem0], imm
                            size_t num0;
                            if (INS_HasScatteredMemoryAccess(branch_set_ins))
                                num0 = INS_MemoryOperandSize(branch_set_ins, 0); 
                            else 
                                num0 = DEFAULT_MEM_READ_SIZE; 
                            
                            INS_InsertCall(branch_set_ins, IPOINT_BEFORE, (AFUNPTR)memory_taint_check_mvi,
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, num0, 
                                IARG_INST_PTR,
                                IARG_END);
                            continue;
                        }
                    }
                    else{
                        if(INS_OperandIsMemory(branch_set_ins, 1)){
                            // cmp imm, [mem1]
                            size_t num1;
                            if (INS_HasScatteredMemoryAccess(branch_set_ins))
                                num1 = INS_MemoryOperandSize(branch_set_ins, 1); 
                            else 
                                num1 = DEFAULT_MEM_READ_SIZE; 
                            INS_InsertCall(branch_set_ins, IPOINT_BEFORE, (AFUNPTR)memory_taint_check_mvi,
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, num1,
                                IARG_INST_PTR,
                                IARG_END);
                            continue;
                        }
                    }
                    
                }
            }
        }
    }
    out.close();
}

int main(int argc, char *argv[]) {

  PIN_InitSymbols();

  if (unlikely(PIN_Init(argc, argv))) {
    std::cerr
        << "Sth error in PIN_Init. Plz use the right command line options."
        << std::endl;
    return -1;
  }

  if (unlikely(libdft_init() != 0)) {
    std::cerr << "Sth error libdft_init." << std::endl;
    return -1;
  }

  hook_file_syscall();
  IMG_AddInstrumentFunction(CmpFuncTrace, 0);
  TRACE_AddInstrumentFunction(DirectCmpHook, 0);
  PIN_StartProgram();

  return 0;
}