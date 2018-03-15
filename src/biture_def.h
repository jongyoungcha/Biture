#ifndef __BITURE_DEF_H__
#define __BITURE_DEF_H__

#include <getopt.h>

#define MAX_CMD        100
#define MODULE_SNIFF   "sniff"
#define MODULE_REPLAY  "replay"
#define MODULE_PRINT   "print"

typedef struct btr_command
{
    char cmd[24];
    void (*fp_desc)();
	int (*fp_func)(struct btr_command* pbtr_cmd, int argc, char* argv[]);
    struct option opt[10];
}btr_command_t;

#endif
