#include <BtrSummaryPrinter.hpp>


BtrSummaryPrinter::BtrSummaryPrinter(const string& name)
{
    cout << "BtrSummaryPrinter()" << endl;
    this->m_ftr_name=name;
}

BtrSummaryPrinter::~BtrSummaryPrinter()
{
}


bool BtrSummaryPrinter::ParseOption(int argc, char* argv[])
{
    return true;
}


void BtrSummaryPrinter::PrintFeatureUsage()
{
}
