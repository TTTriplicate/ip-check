#pragma once
#include "IPCheck.h"

void IPCheck::dataIntake(std::string input) {
    //takes a string, splits on a ' ' to separate ip from mask
    std::regex pattern("[0-9]+");
    std::smatch octet;

    std::string tosearch = input;
    int ip[4];
    int mask[4];

    int count = 0;
    while (std::regex_search(tosearch, octet, pattern)) {
        if (count < 4) {
            ip[count] = stoi(octet.str());
            count++;
            tosearch = octet.suffix();
        }
        else if (count > 8) {
            throw std::invalid_argument("Malformed mask or ip address.");
        }
        else {
            mask[count - 4] = stoi(octet.str());
            count++;
            tosearch = octet.suffix();
        }
    }
    setIP(ip);
    setMask(mask);
    setNetworkAddress();
}

void IPCheck::setIP(int* ip) {
    //breaks the ip address into octets and stores them
    //throws an exception if there are too few, too many, or
    //a number that does not fit in 8 bits unsigned
    for (int i = 0; i < 4; i++) {
        ipAddress[i] = ip[i];
    }
    validateIP();
}

void IPCheck::validateIP() {
    for(int i : ipAddress)
    if (i > 255 || i < 0) {
        throw std::runtime_error("IP Address invalid: octet out of range.");
    }
}

void IPCheck::setMask(int* mask) {
    //breaks the network mask into octets and stores them
    //throws an exception if there are too few, too many,
    //a number that does not fit in 8 bits unsigned,
    //or a pattern other than all 1s followed by all 0s
    for (int i = 0; i < 4; i++) {
        if (mask[i] > 255 || mask[i] < 0) {
            throw std::runtime_error("Network mask invalid: octet out of range.");
        }
        networkMask[i] = mask[i];
    }
    validateMask();
}

void IPCheck::validateMask() {
    for (int i : networkMask)
        if (i > 255 || i < 0) {
            throw std::runtime_error("IP Address invalid: octet out of range.");
        }
    for (int i = 0; i < 4; i++) {
        int submask = 0;
        for (int j = 7; j >= 0; j--) {
            submask += static_cast<int>(std::pow(2, j));
            if (submask == networkMask[i] || networkMask[i] == 0) {
                break;
            }
            else if (submask > networkMask[i]) {
                throw std::runtime_error("Invalid network mask.");
            }
        }
        if (submask != 255) {
            for (int k = i + 1; k < 4; k++) {
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
    //Applies network mask to ip address, stores resulting network address
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
                    return "Class C";
                }
                else {
                    return "Classless";
                }
            }
            else if (networkMask[2] == 0 && networkMask[3] == 0) {
                return "Class B";
            }
            else {
                return "Classless";
            }
        }
        else if (networkMask[1] == 0 && networkMask[2] == 0 && networkMask[3] == 0) {
            return "Class A";
        }
    }
    return "Classless";
}

bool IPCheck::isPublic() {
    //checks rules outlined in RFC 1918; returns true if public, false if not
    if (ipAddress[0] == 10) {
        return false;
    }
    else if (ipAddress[0] == 172) {
        if (ipAddress[1] < 16 || ipAddress[1] > 31) {
            return true;
        }
        else {
            return false;
        }
    }
    else if (ipAddress[0] == 192 && ipAddress[1] == 168) {
        return false;
    }
    else {
        return true;
    }
}