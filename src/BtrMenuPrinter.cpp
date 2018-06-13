#include <BtrMenuPrinter.hpp>


using namespace std;

BtrMenuPrinter::BtrMenuPrinter()
{
}


BtrMenuPrinter::~BtrMenuPrinter()
{
}


bool BtrMenuPrinter::AddSummaryPrinter(BtrSummaryPrinter* ftr_printer)
{
    this->m_ftr_printers.push_back(ftr_printer);
    
    return true;
}


void BtrMenuPrinter::PrintUsage()
{
    for_each(m_ftr_printers.begin(), m_ftr_printers.end(), [](auto ftr){
            ftr->PrintFeatureUsage();
        });
}


void BtrMenuPrinter::PrintFeatureUsage(const string& name)
{
    std::find_if(m_ftr_printers.begin(), m_ftr_printers.end(), [name](BtrSummaryPrinter* const ftr_crr){
            if (name == ftr_crr->Name())
            {
                ftr_crr->PrintFeatureUsage();
                return true;
            }
        });
}
