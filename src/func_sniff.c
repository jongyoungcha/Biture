
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>

#ifdef __APPLE__
#include <mach/error.h>
#else
#include <error.h>
#endif

#include <biture_def.h>
#include <func_sniff.h>
#include <func_common.h>
#include <getopt.h>


char _interface[128]={0};
char _dump_path[8192]={0};
FILE* _fp_todump = NULL;


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

	if (strncmp(_interface, "", strlen(_interface)) == 0)
	{
		fprintf(stderr, "[sniff] You should input a nic interface name...\n");
		return -1;
	}

	fprintf(stdout, "Getted interface : %s\n", _interface);
	fprintf(stdout, "Getted dump_path : %s\n", _dump_path);

	return 0;
}

int func_sniff(btr_command_t* pcmd, int argc, char* argv[])
{
	int ret = 0;
    char* path_dump = NULL;
    char* dname = NULL;
    FILE* pfile = NULL;
    pcap_t* pnic = NULL;
	pcap_if_t* pdev_all = NULL;
	pcap_if_t* pdev = NULL;
	char err_buff[8192] = {0};
	int found_nic = 0;

	ret = func_sniff_parse_args(pcmd, argc, argv);
	if (ret == -1)
	{
		fprintf(stderr, "[sniff] Parsing  was failed...\n");
		return -1;
	}

	if (pcap_findalldevs(&pdev, err_buff) == -1)
	{
		fprintf(stderr, "Finding All nic devs was failed...\n");
		return -1;
	}

	int i = 0;
	for (pdev = pdev_all; pdev; pdev = pdev->next)
	{
		printf("%d. %s", i++, pdev->name);
		if (strcmp(_interface, pdev->name) == 0)
		{
			found_nic = 1;
			break;
		}
	}

    if (found_nic)
    {
		pnic = pcap_open_live(pdev->name,65536, 1, 1000, err_buff);

		pcap_freealldevs(pdev_all);
	
		if (pnic == NULL)
		{
			fprintf(stderr, "pcap_open_live() failed...(err msg : %s)\n", err_buff);
			return -1;
		}
    }
    else
    {
		return 0;
    }
}
