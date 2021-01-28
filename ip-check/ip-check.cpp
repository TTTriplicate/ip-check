/*
ip-check.cpp
written by Chris Sousa
a short program that reads formatted text input
in the form of "(ip address) (network mask)"
and validates input, and outputs analysis.
Written 1/20/21
*/
#include <iostream>
#include <fstream>
#include <math.h>
#include "IPCheck.h"

int main() {
    std::fstream intake("IP.dat");
    std::string line;
    while (getline(intake, line)) {
        IPCheck check;
        try {
            check.dataIntake(line);
        }
        catch (std::runtime_error& e) {
            std::cerr << e.what() << std::endl << std::endl << std::endl;
            continue;
        }
        catch (std::invalid_argument& e) {
            std::cerr << e.what() << std::endl << std::endl << std::endl;
            continue;
        }

        int* ip = check.getIP();
        std::cout << "IP: ";
        for (int i = 0; i < 4; i++) {
            std::cout << ip[i];
            if (i < 3) {
                std::cout << ".";
            }
        }
        std::cout << std::endl;

        int* netAddr = check.getNetworkAddress();
        std::cout << "Network address: ";
        for (int i = 0; i < 4; i++) {
            std::cout << netAddr[i];
            if (i < 3) {
                std::cout << ".";
            }
        }

        std::cout << std::endl;

        std::cout << "Network mask class: " << check.maskClass() << std::endl;

        std::cout << "This network is " << (check.isPublic() ? "Public" : "Private") << std::endl;

        if (check.getIP()[0] == 127) {
            std::cout << "This ip is a loopback address." << std::endl;
        }
        std::cout << std::endl << std::endl;
    }
}