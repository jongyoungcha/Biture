#ifndef _BTR_SUMMARY_PRINTER_HPP_
#define _BTR_SUMMARY_PRINTER_HPP_

#include <BtrCommon.hpp>

using namespace std;

class BtrSummaryPrinter{
public:
    BtrSummaryPrinter(const string& name);
    virtual ~BtrSummaryPrinter()=0;
    virtual bool ParseOption(int argc, char* argv[])=0;
    virtual void PrintFeatureUsage()=0;

    inline string Name() const { return m_ftr_name; }

protected:
private:
    string m_ftr_name;
};


#endif
