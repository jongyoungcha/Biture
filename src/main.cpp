#include <BtrCommon.hpp>
#include <BtrMenuPrinter.hpp>
#include <BtrSniffFeature.hpp>


#include <iostream>
#include <functional>
#include <algorithm>

using namespace std;

#define SNIFF_NAME "sniff"

vector<BtrSummaryPrinter*> _summaries;
BtrMenuPrinter* _menu_printer = NULL;
BtrSniffFeature* _sniff_ftr = NULL;


void initialize()
{
    _sniff_ftr = new BtrSniffFeature(SNIFF_NAME);
    
    _summaries.push_back(_sniff_ftr);

    _menu_printer = new BtrMenuPrinter();
    _menu_printer->AddSummaryPrinter(_sniff_ftr);
}


auto main(int argc, char* argv[]) -> int {

    int ret = 0;
    // bool found = 0;

    initialize();

    cout << "Start Biture..." << endl;

    if (argc < 2)
    {
        cout << "Argument was invalied..." << endl;
        _menu_printer->PrintUsage();
        
        return -1;
    }

    std::find_if(_summaries.begin(), _summaries.end(), [argc, argv](BtrSummaryPrinter* ftr_crr){
            string cmd_name(argv[1]);

            if (ftr_crr->Name() == cmd_name )
            {
                cout << "found command name" << endl;

                char** argv_next = NULL;
                int argc_next = 0;

                argc_next = argc-1; 
                argv_next = &(argv[1]);

                cout << "Try parse options..." << endl;
                if (ftr_crr->ParseOption(argc_next, argv_next) == false)
                {
                    cout << "Parsing job was successful." << endl;
                    return false;
                }

                cout << "Conducting..." << endl;
                BtrOperator* optor = dynamic_cast<BtrOperator*>(ftr_crr);
                if (optor->Conduct() == false)
                {
                    cout << "The job was successful." << endl;
                    return false;
                }

                return true;
            }
        });
    
    return 0;
}



auto curried_add3(int a)
{
    return [a](int b)
    {
        return [a, b](int c)
        {
            return a + b + c;
        };
    };
}


