#include "branch_pred.h"
#include "debug.h"
#include "libdft_api.h"
#include "pin.H"
#include "syscall_hook.h"
#include "tagmap.h"
#include "conditional_hook.h"

#include <iostream>

extern ins_desc_t ins_desc[XED_ICLASS_LAST];
/*
static void
dta_instrument_jmp_call(INS ins)
{

}
*/

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

  hook_all_conditional();
		
  hook_file_syscall();

  PIN_StartProgram();

  return 0;
}
