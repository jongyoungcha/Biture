#ifndef _BTR_MENU_PRINTER_HPP_
#define _BTR_MENU_PRINTER_HPP_

#include <BtrCommon.hpp>
#include <BtrSummaryPrinter.hpp>

using namespace std;

class BtrMenuPrinter{
public:
    BtrMenuPrinter();
    virtual ~BtrMenuPrinter();

    bool AddSummaryPrinter(BtrSummaryPrinter* ftrPrinter);
    void PrintUsage();
    void PrintFeatureUsage(const string& name);
protected:
private:
    vector<BtrSummaryPrinter*> m_ftr_printers;
};



#endif

