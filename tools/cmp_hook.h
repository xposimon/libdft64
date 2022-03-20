/*
 * @Date: 2022-03-11 16:56:04
 * @LastEditors: zx Zhou
 * @LastEditTime: 2022-03-21 01:50:50
 * @FilePath: /libdft64/tools/cmp_hook.h
 */

#ifndef __CMP_HOOK_H__
#define __CMP_HOOK_H__

#include "def.h"
#include "branch_pred.h"
#include "pin.H"
#include "libdft_api.h"
#include "syscall_hook.h"

#include <fstream>
#include <iostream>
#include <vector>

#define CMPFUNCNUM (4)
#define max(a,b) (a>b?a:b)
#ifdef x86 
#define DEFAULT_MEM_READ_SIZE (4)
#else
#define DEFAULT_MEM_READ_SIZE (8)
#endif

class FSFG {
  public:
    FSFG(size_t largest_cmp, size_t addr): largest_cmp(largest_cmp), addr(addr){};
    friend std::ostream & operator<<(std::ostream & os,const FSFG & c);
  private:
    size_t largest_cmp;
    // latency
    // input cor with previous blocks
    size_t addr;
};

std::ostream & operator<<(std::ostream & os,const FSFG & c){
  os << c.addr << ":" << c.largest_cmp;
  return os;
}

size_t tagmap_get_len(ADDRINT addr, unsigned int n);
VOID strcmp_hook(const char* s1, const char* s2, size_t ret_addr);
VOID memcmp_hook(const void * ptr1, const void * ptr2, size_t num, size_t ret_addr);
VOID strncmp_hook(const char * ptr1, const char * ptr2, size_t num, size_t ret_addr);
VOID strrchr_hook( const char * str, int character, size_t ret_addr );

/*
Ins Category:
  14 add/sub/cmp
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

VOID memory_taint_check_mvi(ADDRINT mem_addr, size_t num, ADDRINT ret_addr);
VOID memory_taint_check_mvm(ADDRINT mem_adr0, ADDRINT mem_addr1, size_t num0, size_t num1, ADDRINT ret_addr);
VOID reg_taint_check(THREADID tid, unsigned int reg_idx, size_t n, size_t ret_addr);
VOID DirectCmpHook(TRACE trace, VOID *v);

#endif