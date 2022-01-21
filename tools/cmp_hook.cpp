/*
 * @Date: 2021-12-06 21:52:44
 * @LastEditors: zx Zhou
 * @LastEditTime: 2022-01-21 22:48:24
 * @FilePath: /libdft64/tools/cmp_hook.cpp
 */
#include "branch_pred.h"
#include "pin.H"
#include "libdft_api.h"
#include "syscall_hook.h"
#include <iostream>

#define max(a,b) (a>b?a:b)

typedef struct {
  size_t largest_cmp;
  // latency
  // input cor with previous blocks
  size_t addr; 
} FSFG;

FSFG* fuzz_sfg;

size_t tagmap_get_len(ADDRINT addr, unsigned int n) {
  size_t tag_len = 0;
  for (size_t i = 0; i < n; i++) {
    const tag_t t = tagmap_getb(addr + i);
    if (tag_is_empty(t))
      continue;
    // LOGD("[tagmap_getn] %lu, ts: %d, %s\n", i, ts, tag_sprint(t).c_str());
    tag_len ++;
  }
  return tag_len;
}

// strcmp: sub eax, ecx
//         jne loc
// one-byte cmp: cmp al, 0x68
//               jne loc

#define CMPFUNCNUM (4)
const char* cmp_functions[CMPFUNCNUM] = {"strcmp", "memcmp", "strncmp", "strrchr"};

VOID strcmp_hook(const char* s1, const char* s2, size_t ret_addr){
    if (ret_addr > 0x7fffffffffff) {
      return;
    }
    size_t len1 = strlen(s1), len2 = strlen(s2);
    // tag_t t1 = tagmap_getn((ADDRINT)s1, len1);
    // tag_t t2 = tagmap_getn((ADDRINT)s2, len2);
    size_t tagl1 = tagmap_get_len((ADDRINT)s1, len1);
    size_t tagl2 = tagmap_get_len((ADDRINT)s2, len2);
    printf("[+] strcmp cmp len: %ld, addr: %lx\n", max(tagl1, tagl2), ret_addr);
}

VOID memcmp_hook(const void * ptr1, const void * ptr2, size_t num, size_t ret_addr){
    if (ret_addr > 0x7fffffffffff) {
      return;
    }
    size_t tagl1 = tagmap_get_len((ADDRINT)ptr1, num);
    size_t tagl2 = tagmap_get_len((ADDRINT)ptr2, num);
    printf("[+] memcmp cmp len: %ld, addr: %lx\n", max(tagl1, tagl2), ret_addr);
}

VOID strncmp_hook(const char * ptr1, const char * ptr2, size_t num, size_t ret_addr){
    if (ret_addr > 0x7fffffffffff) {
      return;
    }
    size_t tagl1 = tagmap_get_len((ADDRINT)ptr1, num);
    size_t tagl2 = tagmap_get_len((ADDRINT)ptr2, num);
    printf("[+] strncmp cmp len: %ld, addr: %lx\n", max(tagl1, tagl2), ret_addr);

}

VOID strrchr_hook( const char * str, int character, size_t ret_addr ){
    if (ret_addr > 0x7fffffffffff) {
      return;
    }
    size_t largest_cmp = 0;

    size_t len1 = strlen(str);
    size_t tagl1 = tagmap_get_len((ADDRINT)str, len1);
    size_t tagl2 = tagmap_get_len((ADDRINT)character, 1);
    if (tagl2 != 0){
      largest_cmp = tagl2;
    }
    else{
      largest_cmp = max(tagl1, tagl2);
    }
    printf("[+] strrchr cmp len: %ld, addr: %lx\n", largest_cmp, ret_addr);
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

/*
Ins Category:
  14 sub/cmp
  15 bt
  26 cmovnz
  31 mov/movups
  49 test 
  52 lea
  60 pop
  64 push
  79 sar/shr
  81 pshufd
  99 nop
*/

int cnt =0;

VOID memory_taint_check(ADDRINT mem_addr1, ADDRINT mem_addr2)
{
    printf("%ld %ld\n", mem_addr1, mem_addr2);
}

VOID DirectCmpHook(TRACE trace, VOID *v)
{
    //size_t cmp_len = 0;
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)){
        INS tail_ins = BBL_InsTail(bbl);
        if (INS_Valid(tail_ins) && INS_IsBranch(tail_ins)){    
            INS branch_set_ins = INS_Prev(tail_ins);
            if (INS_IsOriginal(branch_set_ins)){
                int cat = INS_Category(branch_set_ins);
                // sub && cmp
                if (cat == 14){
                    //printf("[++] %d\n", cnt ++);
                    
                    //printf("[dis] %s : [cate] %d\n", INS_Disassemble(branch_set_ins).c_str(), cat);
 
                    if (INS_OperandIsMemory(branch_set_ins, 0) || INS_OperandIsMemory(branch_set_ins, 1)){
                            INS_InsertCall(branch_set_ins, IPOINT_BEFORE, (AFUNPTR)memory_taint_check,
                            IARG_MEMORYREAD_EA,
                            IARG_MEMORYREAD2_EA,
                            IARG_END);
                            continue;
                    }

                    for (int reg_i = 0; reg_i < 2; reg_i ++){
                        if (INS_OperandIsReg(branch_set_ins, reg_i)){
                            //REG reg = INS_OperandReg(branch_set_ins, reg_i);
                            //printf("reg[%d] %s\n", reg_i, REG_StringShort(reg).c_str());
                            continue;
                        }
                    }
                }
            }
        }
    }
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