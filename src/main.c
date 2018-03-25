#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <func_sniff.h>
#include <biture_def.h>

int find_nic_from_system();
void desc_sniff();
void desc_replay();
void desc_print();

void desc_sniff()
{
	printf("Sample usage : > ./bitrue sniff -i eth0 -d ./dumpfile\n");
	printf("Valid options:\n");
	printf("-i [--interface] : a nic interface from this system.\n");
	printf("-d [--dumppath] : a path of dump file.\n");
	printf("-f [--filter] : a filter string used sniffing\n");
	printf("\n");
}

void desc_replay()
{
    printf("desc_replay()\n");
}

void desc_print()
{
    printf("desc_print()\n");
}

int func_replay(struct btr_command* pcmd, int argc, char* argv[]);
int func_print(struct btr_command* pcmd, int argc, char* argv[]);

btr_command_t cmds[] = {
	{MODULE_SNIFF, desc_sniff, func_sniff, {{"interface", required_argument, NULL, 'i'},
											{"dumppath", required_argument, NULL, 'd'}}},
    {MODULE_REPLAY, desc_replay, func_replay, {{"dumpfile", required_argument, 0, 'f'},
											   {"interface-to-send", required_argument, 0, 'i'}}},
    {MODULE_PRINT, desc_print, func_print, {{"dumpfile", required_argument, 0, 'f'},
											{"delay", required_argument, 0, 'd'}}}
};

#define CMD_SIZE ((int) (sizeof(cmds) / sizeof (*cmds)))

pcap_t* find_open_nic(const char* interface);
void print_packet_handler(u_char* args, const struct pcap_pkthdr *packet_header, const u_char* packet);
int ants_str2hex(char* str, char* str_hex, int len_limit, char* delimit);

int ants_str2hex(char* str, char* str_hex, int len_limit, char* delimit)
{
    int ret = 0;
    int len_hex = 0;
    
    unsigned char* offs_str = NULL;

    if (str == NULL || str_hex == NULL || len_limit <= 0)
    {
		return  -1;
    }

    for (offs_str = (unsigned char*)str;
		 *offs_str != '\0';
		 offs_str++)
    {
		if (++len_hex > len_limit)
		{
			fprintf(stderr, "Length of hex was longer than limit.\n");
			return -1;
		}
	
		sprintf(str_hex + strlen(str_hex), "%x", *offs_str);
	
		if (delimit)
		{
			if (( len_hex += strlen(delimit )) > len_limit)
			{
				return -1;
			}
	    
			sprintf(str_hex + strlen(str_hex), "%s", delimit);
		}
    }

    return ret;
}



pcap_t* find_open_nic(const char* interface)
{
    int ret=0;
    char* device;
    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap_t* pnic = NULL;
    pcap_if_t *alldevs;
    pcap_if_t *d;

    int found_nic = 0;

    device = pcap_lookupdev(error_buffer);
    if (device == NULL)
    {
		fprintf(stderr, "%s\n", error_buffer);
		return NULL;
    }

    printf("getting dev : %s\n", device);

    ret = pcap_findalldevs(&alldevs, error_buffer);
    if (ret == -1)
    {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", error_buffer);
		return NULL;
    }

    for (d = alldevs; d; d=d->next)
    {
		if (strcmp(interface, d->name) == 0)
		{
			found_nic = 1;
			break;
		}
    }

    if (found_nic)
    {
		pnic = pcap_open_live(d->name,65536, 1, 1000, error_buffer);

		pcap_freealldevs(alldevs);
	
		if (pnic == NULL)
		{
			fprintf(stderr, "pcap_open_live() failed...(err msg : %s)\n", error_buffer);
			return NULL;
		}
		else
		{
			return pnic;
		}
    }
    else
    {
		return NULL;
    }
}


void print_packet_handler(u_char* args, const struct pcap_pkthdr *packet_header, const u_char* packet)
{
    char buf[8192] = {0};
    
    printf("Packet capture length : %d\n", packet_header->caplen);
    printf("Packet total length : %d\n", packet_header->len);

    ants_str2hex((char*)packet, buf, packet_header->caplen, " | ");
	printf("%s", buf);

    return;
}


int func_replay(struct btr_command* pcmd, int argc, char* argv[])
{
    return 0;
}


int func_print(struct btr_command* pcmd, int argc, char* argv[])
{
    return 0;
}


void help()
{
    int i;
    printf("Biture command-line client.\n");
    printf("Available subcommands : \n");
    printf("\n");

    for (i=0; i<CMD_SIZE; i++)
    {
		printf("%s\n", cmds[i].cmd);
    }
}


int main(int argc, char* argv[])
{
    int i = 0;
	int ret = 0;
    struct btr_command* pcmd = NULL;
    char* cmd_user = NULL;

    printf("size : %d\n", CMD_SIZE);

    if ( argc < 2 )
    {
		help();
		exit(EXIT_FAILURE);
    }
    else
    {
		cmd_user = argv[1];
		for (i=0; i<CMD_SIZE; i++)
		{
			if(strncmp(cmds[i].cmd, cmd_user, strlen(cmds[i].cmd)) == 0)
			{
				printf("found the command(command : %s)\n", cmd_user);
				pcmd = &cmds[i];
				break;
			}
		}
    }

    if (pcmd)
    {
		ret = pcmd->fp_func(pcmd, argc, argv);
		if (ret == -1)
		{
			printf("Biture was failed...\n");
			pcmd->fp_desc();
			
			return -1;
		}
    }
    else
    {
		printf("could not found the (%s)\n", cmd_user);
    }
    
    return 0;
}




