#ifndef __CONDITIONAL_HOOK_H
#define __CONDITIONAL_HOOK_H
#include "libdft_api.h"

#include<string>

extern ins_desc_t ins_desc[XED_ICLASS_LAST];

static void
pre_jz_hook(INS ins)
{
	std::string addr = StringFromAddrint(INS_Address(ins));
	std::string dis = INS_Disassemble(ins);
	printf("[*] hook %d %s:%s\n", INS_IsBranch(ins), addr.c_str(), dis.c_str());
}

static void
pre_jnz_hook(INS ins)
{
	std::string addr = StringFromAddrint(INS_Address(ins));
	std::string dis = INS_Disassemble(ins);
	printf("[*] hook %d %s:%s\n", INS_IsBranch(ins), addr.c_str(), dis.c_str());
}

void hook_all_conditional()
{
	(void)ins_set_pre(&ins_desc[XED_ICLASS_JZ],
			pre_jz_hook);
	(void)ins_set_pre(&ins_desc[XED_ICLASS_JNZ],
			pre_jnz_hook);
}
#endif 
