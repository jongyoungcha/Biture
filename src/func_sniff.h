#ifndef __SNIFF_FUNC_H__
#define __SNIFF_FUNC_H__

#include <biture_def.h>
#include <biture_common.h>


int func_sniff_parse_args(btr_command_t* pcmd, int argc, char* argv[]);
int func_sniff(btr_command_t* pcmd, int argc, char* argv[]);

#endif
