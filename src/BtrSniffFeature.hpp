#ifndef _BTR_SNIFF_FEATURE_HPP_
#define _BTR_SNIFF_FEATURE_HPP_

#include <BtrCommon.hpp>
#include <BtrSummaryPrinter.hpp>
#include <BtrOperator.hpp>

#define DUMP_PATH_LIMIT 1024


static struct option sniff_options[] = {
    {"interface", required_argument, NULL, 'i'},
    {"dumppath", required_argument, NULL, 'd'}
};

typedef struct _btr_caploop_arg{
    int width_chunk;
    int width_line;
    char dump_path[1024];
} btr_caploop_arg;


class BtrSniffFeature : virtual public BtrSummaryPrinter, virtual public BtrOperator {
public:
    BtrSniffFeature(const string& name);
    virtual ~BtrSniffFeature();
    virtual bool ParseOption(int argc, char* argv[]);
    virtual bool Conduct();
    virtual void PrintFeatureUsage();
    
    bool SniffBytes(const string interface, const string filter, const string dumppath);
    bool DumpFile(vector<unsigned char> &vec_bytes, int width);
    bool SetFilter(string filter);
    
    static void PcapCallback(u_char* param, const struct pcap_pkthdr* header, const u_char *pkt_data);
    
protected:
private:
    string m_interface;
    string m_dumppath;
    string m_filter;
    int m_width_chunk;
    int m_width_line;
};

#endif
