#pragma once
#include "IPCheck.h"

void IPCheck::dataIntake(std::string input) {
    //uses regex to parse out the octets of the ip address and network mask.
    //throws if there are too few or too many octets
    std::regex pattern("\\d+");
    std::smatch octet;
    std::string tosearch = input;
    int ip[4];
    int mask[4];

    int count = 0;
    auto matches = std::sregex_iterator(input.begin(), input.end(), pattern);
    auto end = std::sregex_iterator();
    for (std::sregex_iterator i = matches; i != end; i++) {
        if (count < 4) {//first four octets are ip address
            octet = *i;
            ip[count] = stoi(octet.str());
            count++;
        }
        else if (count > 7) {//too many octets caught here
            throw std::invalid_argument(input + ": \nMalformed mask or ip address.");
        }
        else {//next 4 are network mask
            octet = *i;
            mask[count - 4] = stoi(octet.str());
            count++;
        }
    }
    setIP(ip);
    setMask(mask);
    setNetworkAddress();
}

void IPCheck::setIP(int* ip) {
    //stores the ip address
    for (int i = 0; i < 4; i++) {
        ipAddress[i] = ip[i];
    }
    validateIP();
}

void IPCheck::validateIP() {
    //Throws if there is a number that does not fit in 8 bits unsigned
    //also catches too few octets; default is INT_MIN, far less than 0
    for(int i : ipAddress)
    if (i > 255 || i < 0) {
        throw std::runtime_error("IP Address invalid: octet out of range.");
    }
}

void IPCheck::setMask(int* mask) {
    //stores the network mask
    for (int i = 0; i < 4; i++) {
        networkMask[i] = mask[i];
    }
    validateMask();
}

void IPCheck::validateMask() {
    //Throws if there is a number that does not fit in 8 bits unsigned,
    //or a pattern other than all 1s followed by all 0s
    for (int i : networkMask)
        if (i > 255 || i < 0) {
            throw std::runtime_error("Network mask invalid: octet out of range.");
        }
    for (int i = 0; i < 4; i++) {
        int submask = 0;
        for (int j = 7; j >= 0; j--) {
            //valid submasks are 1s  then 0s, left to right
            //with 8 bits per octet, it will be the sum of i^2 from i=7 to i=0
            submask += static_cast<int>(std::pow(2, j));
            if (submask == networkMask[i] || networkMask[i] == 0) {
                break;
            }
            else if (submask > networkMask[i]) {//zeros too early in sequence
                throw std::runtime_error("Invalid network mask.");
            }
        }
        if (submask != 255) {
            for (int k = i + 1; k < 4; k++) {
                //any non-zero octet following a octet < 255 is invalid
                if (networkMask[k] != 0) {
                    throw std::runtime_error("Invalid network mask.");
                }
            }
        }
    }
}

int* IPCheck::getIP() {
    return ipAddress;
}

int* IPCheck::getMask() {
    return networkMask;
}

void IPCheck::setNetworkAddress() {
    //Applies network mask to ip address using bitwise and; stores resulting network address
    for (int i = 0; i < 4; i++) {
        networkAddress[i] = (ipAddress[i] & networkMask[i]);
    }
}

int* IPCheck::getNetworkAddress() {
    return networkAddress;
}

std::string IPCheck::maskClass() {
    //determines if the network mask falls into any of the legacy categories
    if (networkMask[0] == 255) {
        if (networkMask[1] == 255) {
            if (networkMask[2] == 255) {
                if (networkMask[3] == 0) {
                    //255.255.255.0
                    return "Class C";
                }
                else {
                    return "Classless";
                }
            }
            else if (networkMask[2] == 0 && networkMask[3] == 0) {
                //255.255.0.0
                return "Class B";
            }
            else {
                return "Classless";
            }
        }
        else if (networkMask[1] == 0 && networkMask[2] == 0 && networkMask[3] == 0) {
            //255.0.0.0
            return "Class A";
        }
    }
    return "Classless";
}

bool IPCheck::isPublic() {
    //checks rules outlined in RFC 1918; returns true if public, false if not
    if (ipAddress[0] == 10) {
        //10.x.x.x
        return false;
    }
    else if (ipAddress[0] == 172) {
        if (ipAddress[1] < 16 || ipAddress[1] > 31) {
            return true;
        }
        else {
            //172.16-31.x.x
            return false;
        }
    }
    else if (ipAddress[0] == 192 && ipAddress[1] == 168) {
        //192.168.x.x
        return false;
    }
    else {
        return true;
    }
}