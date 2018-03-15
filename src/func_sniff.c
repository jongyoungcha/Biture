
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <errno.h>
#include <biture_def.h>
#include <func_sniff.h>
#include <func_common.h>
#include <getopt.h>


char _interface[128]={0};
char _dump_path[8192]={0};


int func_sniff_parse_args(btr_command_t* pcmd, int argc, char* argv[])
{
	int ret = 0;
	int i=0;
	int opt = 0;
	char opts[10] = {0};

	for (i=0; i<10; i++)
	{
		printf("%c\n", pcmd->opt[i].val);
		snprintf(opts, sizeof(opts)-strlen(opts), "%s%c", opts, pcmd->opt[i].val);
	}
	printf("%s\n", opts);


	while((opt = getopt(argc, argv, "i:d:")) != -1)
	{
		switch(opt)
		{
		case 'i':
			snprintf(_interface, sizeof(_interface), "%s",optarg);
			printf("Getted nic interface : %s\n", _interface);
			break;
			
			
		case 'd':
			snprintf(_dump_path, sizeof(_dump_path), "%s", optarg);
			printf("Path of packet dump file : %s\n", _dump_path);  
			break;
		default :
			return -1;
		}
	}

	return 0;
}

int func_sniff(btr_command_t* pcmd, int argc, char* argv[])
{
	int ret = 0;
    char* path_dump = NULL;
    char* dname = NULL;
    FILE* pfile = NULL;
    pcap_t* pnic = NULL;

	ret = func_sniff_parse_args(pcmd, argc, argv);
	if (ret == -1)
	{
		fprintf(stderr, "[sniff] Parsing  was failed...\n");
		return -1;
	}
		

    /* if (path) */
    /* { */
	/* 	printf("here!!!\n"); */
	/* 	sleep(1); */
	/* 	path_dump = strdup(path); */
	/* 	dname = dirname(path_dump); */

	/* 	if (access(dname, F_OK) != 0) */
	/* 	{ */
	/* 		fprintf(stderr, "A Base directory counldnt found...(%s)\n", dname);  */
	/* 		exit(EXIT_FAILURE); */
	/* 	} */

	/* 	if (access(path, F_OK) == 0) */
	/* 	{ */
	/* 		fprintf(stderr, "The path was existing...(%s)\n", path); */
	/* 		exit(EXIT_FAILURE); */
	/* 	} */

	/* 	pfile = fopen(path, "w"); */
	/* 	if (!pfile) */
	/* 	{ */
	/* 		fprintf(stderr, "Counldnt open file (%s)\n", strerror(errno)); */
	/* 		exit(EXIT_FAILURE); */
	/* 	} */
    /* } */
    /* else */
    /* { */
    /* 	pfile = stdout; */
    /* } */

    /* /\* Find the nic and open() *\/ */
    /* pnic = find_open_nic(interface); */

    if(pnic)
    {
		/* pcap_loop(pnic, 0, print_packet_handler, NULL); */
		return 0;
    }
	else
	{
		fprintf(stderr, "The name of nic was not existing...\n");
		return -1;
	}
}
