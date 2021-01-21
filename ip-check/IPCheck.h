/*
Class IPCheck
A class to handle reading and evaluating ip addresses
and network masks
*/
#pragma once
#include <cstdint>
#include <string>
#include <stdexcept>
#include <iostream>

class IPCheck {
private:
    int ipAddress[4];
    void setIP(std::string address);

    int networkMask[4];
    void setMask(std::string mask);
    int* getMask();

    int networkAddress[4];
    void setNetworkAddress();

public:
    IPCheck() {};
    void dataIntake(std::string input);
    int* getIP();
    int* getNetworkAddress();
    std::string maskClass();
    bool isPublic();
};