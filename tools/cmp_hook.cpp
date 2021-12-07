/*
 * @Date: 2021-12-06 21:52:44
 * @LastEditors: zx Zhou
 * @LastEditTime: 2021-12-08 00:27:13
 * @FilePath: /libdft64/tools/cmp_hook.cpp
 */
#include "branch_pred.h"
#include "pin.H"
#include "libdft_api.h"
#include "syscall_hook.h"
#include <iostream>

#define CMPFUNCNUM (2)

size_t tagmap_get_len(ADDRINT addr, unsigned int n) {
  size_t tag_len = 0;
  for (size_t i = 0; i < n; i++) {
    const tag_t t = tagmap_getb(addr + i);
    if (tag_is_empty(t))
      continue;
    // LOGD("[tagmap_getn] %lu, ts: %d, %s\n", i, ts, tag_sprint(t).c_str());
    tag_len ++;
    // LOGD("t: %d, ts:%d\n", t, ts);
  }
  return tag_len;
}

// strcmp: sub eax, ecx
//         jne loc
// one-byte cmp: cmp al, 0x68
//               jne loc

const char* cmp_functions[10] = {"strcmp", "memcmp"};

size_t largest_cmp = 0;

VOID strcmp_hook(const char* s1, const char* s2)
{
    size_t len1 = strlen(s1), len2 = strlen(s2);
    // tag_t t1 = tagmap_getn((ADDRINT)s1, len1);
    // tag_t t2 = tagmap_getn((ADDRINT)s2, len2);
    size_t tagl1 = tagmap_get_len((ADDRINT)s1, len1);
    size_t tagl2 = tagmap_get_len((ADDRINT)s2, len2);
    // tag_t t3;
    // for (int i = 3; i < 43; i++){
    //     t3 = tagmap_getn_reg(tid, i, 8);
    //     printf("[%d]::%s\n",i,tag_sprint(t3).c_str());
    // }
    largest_cmp = tagl1>tagl2?tagl1:tagl2;
}

VOID memcmp_hook(const void * ptr1, const void * ptr2, size_t num )
{
    tag_t t1 = tagmap_getn((ADDRINT)ptr1, num);
    tag_t t2 = tagmap_getn((ADDRINT)ptr2, num);
    size_t tagl1 = tagmap_get_len((ADDRINT)ptr1, num);
    size_t tagl2 = tagmap_get_len((ADDRINT)ptr2, num);
    printf("[+] [%ld] %s :: [%ld] %s \n", tagl1, tag_sprint(t1).c_str(), tagl2, tag_sprint(t2).c_str());
}


VOID strncmp_hook(const char * str1, const char * str2, size_t num );
VOID strrchr_hook( const char * str, int character );
VOID strcoll_hook( const char * str1, const char * str2 );

VOID CmpFuncTrace(IMG img, VOID *v)
{
    // Instrument the malloc() and free() functions.  Print the input argument
    // of each malloc() or free(), and the return value of malloc().
    for (unsigned int cmp_func_idx = 0; cmp_func_idx < CMPFUNCNUM; cmp_func_idx ++){
        RTN rtn = RTN_FindByName(img, cmp_functions[cmp_func_idx]);  //  Find the malloc() function.
        if (RTN_Valid(rtn)){
            printf("%s\n", RTN_Name(rtn).c_str());

            RTN_Open(rtn);
            switch (cmp_func_idx){
              case 0:
                  RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcmp_hook,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_END);
                  break;
              case 1:
                  RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memcmp_hook,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_END);
                  break;
            }	
            RTN_Close(rtn);
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

  //TRACE_AddInstrumentFunction(DiffEvalTrace, 0); 
//   INS_AddInstrumentFunction(DiffEvalInsTrace, 0);

//   PIN_AddApplicationStartFunction(DiffEvalInsTrace, 0);
  
  hook_file_syscall();
  IMG_AddInstrumentFunction(CmpFuncTrace, 0);
  PIN_StartProgram();
  

  return 0;
}