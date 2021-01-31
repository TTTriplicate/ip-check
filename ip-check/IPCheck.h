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
#include <regex>

class IPCheck {
private:
    int ipAddress[4];
    void setIP(int * ip);
    void validateIP();

    int networkMask[4];
    void setMask(int * mask);
    void validateMask();

    int networkAddress[4];
    void setNetworkAddress();

public:
    IPCheck() {};
    void dataIntake(std::string input);
    int* getIP();
    int* getMask();
    int* getNetworkAddress();
    std::string maskClass();
    bool isPublic();
};