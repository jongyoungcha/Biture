#include <BtrSniffFeature.hpp>
#include <BtrSummaryPrinter.hpp>
#include <stdlib.h>


BtrSniffFeature::BtrSniffFeature(const string& name) : BtrSummaryPrinter(name), BtrOperator()
{
    cout << "BtrSniffFeature()" << endl;
    this->m_width_chunk = 4;
    this->m_width_line = 16;
}


BtrSniffFeature::~BtrSniffFeature()
{
    cout << "~BtrSniffFeature()" << endl;
}


bool BtrSniffFeature::ParseOption(int argc, char* argv[])
{
    int c = 0;
    int opt_index = 0;

    while(1)
    {
        c = getopt_long(argc, argv, "i:d:", sniff_options, &opt_index);
        if (c == -1)
        {
            break;
        }

        switch (c)
        {
        case 0:
            break;
        case 'i':
            cout << "option i : " << optarg << endl;
            this->m_interface = optarg;
            break;
        case 'd':
            cout << "option d : " << optarg << endl;
            this->m_dumppath = optarg;
            break;
        defualt:
            abort();
        }
    }

    return true;
}

    
bool BtrSniffFeature::Conduct()
{
    cout << "In conduct ()...." << endl;
    if (m_interface!="")
    {
        string filter;
        if (m_filter.empty()==false)
        {
            filter=m_filter;
        }

        string dumppath;
        if (m_dumppath.empty()==false)
        {
            dumppath=m_dumppath;
        }

        cout << "SniffBytes()" << endl;
        if (SniffBytes(m_interface, filter, dumppath) == false)
        {
            cout << "Could not sniffing..." << endl;
        }
    }
    
    return true;
}


void BtrSniffFeature::PcapCallback(u_char* param, const struct pcap_pkthdr* header, const u_char *pkt_data)
{
    long i = 0;
    int cnt = 0;
    FILE* fp_out = NULL;
    btr_caploop_arg* args = (btr_caploop_arg*)param;
                                                        
    if (strcmp(args->dump_path, "")!=0)
    {
        fp_out = fopen(args->dump_path, "a+");
    }
    else
    {
        fp_out = stdout;
    }

    fprintf(fp_out, "\n");
    
    for (i=0; i<header->caplen; i++)
    {
        fprintf(fp_out, "%02X ", pkt_data[i]);
        cnt++;
        if (cnt % args->width_chunk == 0)
        {
            fprintf(fp_out, "| ");
        }
        if (cnt == args->width_line)
        {
            fprintf(fp_out, "\n");
            cnt = 0;
        }
    }
    if (fp_out && fp_out != stdout)
    {
        fclose(fp_out);
    }
}


bool BtrSniffFeature::SniffBytes(const string interface, const string filter, const string dumppath)
{
    char* dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *hdl_dev = NULL;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    btr_caploop_arg *args;

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        fprintf(stderr, "Could not find the interface...(%s)\n", errbuf);
        exit(EXIT_FAILURE);
    }

    hdl_dev = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    
    if (!hdl_dev)
    {
        fprintf(stderr, "Openning the interface was failed...(%s)", errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_compile(hdl_dev, &fp, filter.c_str(), 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s : %s\n", filter.c_str(), pcap_geterr(hdl_dev));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(hdl_dev, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s : %s\n", filter.c_str(), pcap_geterr(hdl_dev));
        exit(EXIT_FAILURE);
    }

    args = (btr_caploop_arg*)malloc(sizeof(btr_caploop_arg));
    memset(args, 0x00, sizeof(btr_caploop_arg));

    args->width_chunk = this->m_width_chunk;
    args->width_line = this->m_width_line;
    if (dumppath.empty()==false) snprintf(args->dump_path, sizeof(args->dump_path), "%s", dumppath.c_str());
    
    if (pcap_loop(hdl_dev, 0, BtrSniffFeature::PcapCallback, (u_char*)args) == -1)
    {
        fprintf(stderr, "Couldn't success pcap_loop(%s : %s)\n", filter.c_str(), pcap_geterr(hdl_dev));
        exit(EXIT_FAILURE);
    }

    cout << "Done..." << endl;
    while(1) {sleep(1);}

    return true;
}



bool BtrSniffFeature::DumpFile(vector<unsigned char> &vec_bytes, int width)
{
    const string dumppath = this->m_dumppath;
    ofstream file;

    try{
        file.open(dumppath.c_str(), ios::out);        
    }
    catch (...)
    {
        return false;
    }

    for_each(vec_bytes.begin(), vec_bytes.end(),[&file](auto byte){
            file << byte << endl;
        });

    return true;
}


bool BtrSniffFeature::SetFilter(string filter)
{
    
    return true;
}



void BtrSniffFeature::PrintFeatureUsage()
{
    cout << "Spample usage : > ./bitrue sniff -i eth0 -d ./dumpfile" << endl;
	cout << "Valid options : " << endl;
	cout << "-i [--interface] : a nic interface from this system." << endl;
	cout << "-d [--dumppath] : a path of dump file." << endl;
	cout << "-f [--filter] : a filter string used sniffing." << endl;
    cout << endl;
}
