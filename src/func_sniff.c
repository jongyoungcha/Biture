#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <pcap.h>
#include <time.h>
#include <libgen.h>

#ifdef __APPLE__
#include <mach/error.h>
#else
#include <error.h>
#endif

#include <biture_def.h>
#include <func_sniff.h>
#include <func_common.h>
#include <getopt.h>

int _is_run_sniff = 1;
char _interface[128] = {0};
char _dump_path[8192] = {0};
FILE* _fp_todump = NULL;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct ether_header *peh = NULL;
	struct ip *piph = NULL;
	struct tcphdr *ptcph = NULL;
	unsigned short ether_type;
	int chcnt =0;
	int length=header->len;	

	peh = (struct ether_header*)pkt_data;
	pkt_data += sizeof(struct ether_header);

	ether_type = ntohs(peh->ether_type);
	if (ether_type == ETHERTYPE_IP)
	{
		fprintf(stdout, "This is ethernet packet!!\n");

		piph = (struct ip*)pkt_data;
		fprintf(_fp_todump,"IP packet\n");
		fprintf(_fp_todump, "Version : %d\n", piph->ip_v);
		fprintf(_fp_todump, "Header Len : %d\n", piph->ip_hl);
		fprintf(_fp_todump, "Ident      : %d\n", ntohs(piph->ip_id));
		fprintf(_fp_todump, "TTL      : %d\n", ntohs(piph->ip_ttl));
		fprintf(_fp_todump, "Src Address : %s\n", inet_ntoa(piph->ip_src));
		fprintf(_fp_todump, "Dst Address : %s\n", inet_ntoa(piph->ip_dst));
		
		if (piph->ip_p == IPPROTO_TCP)
		{
			ptcph = (struct tcphdr*)(pkt_data + piph->ip_hl * 4);
			printf("Src Port : %d\n", ntohs(ptcph->source));
			printf("Dst Port : %d\n", ntohs(ptcph->dest));
		}

		fflush(_fp_todump);
		
		/* while(length--) */
		/* { */
		/* 	printf("%02x ", *(pkt_data++)); */
		/* 	if((++chcnt % 16) == 0) */
		/* 	{ */
		/* 		printf("\n"); */
		/* 	} */
		/* } */
	}
	else
	{
		fprintf(stdout, "This is not ethernet packet!!\n");
	}

	return;
}

int func_sniff_parse_args(btr_command_t* pcmd, int argc, char* argv[])
{
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
			snprintf(_interface, sizeof(_interface), "%s", optarg);
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

	if (strcmp(_dump_path, "") != 0)
	{
		_fp_todump = fopen(_dump_path, "w");
		if (_fp_todump == NULL)
		{
			fprintf(stderr, "Opening dump file was failed..(path : %s)\n", _dump_path);
			return -1;
		}
	}
	else
	{
		_fp_todump = stdout;
	}
	
	if (pcap_findalldevs(&pdev_all, err_buff) == -1)
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
		pnic = pcap_open_live(pdev->name, 65536, 1, 1000, err_buff);
		if (pnic == NULL)
		{
			fprintf(stderr, "pcap_open_live() failed...(err msg : %s)\n", err_buff);
			if (pdev_all) pcap_freealldevs(pdev_all);
			return -1;
		}
		else
		{
			pcap_loop(pnic, 0, packet_handler, NULL);

			while(1)
			{
				sleep(1);
			}
		}
    }
	else
	{
		fprintf(stderr, "Could not find any nic...\n");
	}
	
	return -1;
}
