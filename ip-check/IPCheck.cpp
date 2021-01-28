#pragma once
#include "IPCheck.h"

void IPCheck::dataIntake(std::string input) {
    //takes a string, splits on a ' ' to separate ip from mask
    std::string ip, mask;
    ip = input.substr(0, input.find(" "));
    mask = input.substr(input.find(" ")+1);
    if (mask == "" || mask == " ") {
        try {
            mask = input.substr(1, input.find(" "));
        }
        catch (std::exception e) {
            throw std::runtime_error("bad data entered.");
        }
    }
    setIP(ip);
    setMask(mask);
    setNetworkAddress();
}

void IPCheck::setIP(std::string ip) {
    //breaks the ip address into octets and stores them
    //throws an exception if there are too few, too many, or
    //a number that does not fit in 8 bits unsigned
    int count = 0;
    size_t pos = 0;
    std::string fullIP = ip;
    while ((pos = ip.find(".")) != std::string::npos) {
        ipAddress[count] = stoi(ip.substr(0, pos));
        if (ipAddress[count] > 255 || ipAddress[count] < 0) {
            throw std::runtime_error("IP Address invalid: " + fullIP);
        }
        count++;
        ip.erase(0, pos + 1);
    }
    if (count == 3) {
        ipAddress[3] = stoi(ip);
    }
    else {
        throw std::runtime_error("IP Address invalid: " + fullIP);
    }
}

void IPCheck::setMask(std::string mask) {
    //breaks the network mask into octets and stores them
    //throws an exception if there are too few, too many,
    //a number that does not fit in 8 bits unsigned,
    //or a pattern other than all 1s followed by all 0s
    size_t pos = 0;
    int count = 0;
    std::string fullMask = mask;
    while ((pos = mask.find(".")) != std::string::npos) {
        networkMask[count] = stoi(mask.substr(0, pos));
        count++;
        mask.erase(0, pos + 1);
    }
    if (count == 3) {
        networkMask[3] = stoi(mask);
    }
    else {
        throw std::runtime_error("Invalid network mask: " + fullMask);
    }
    for (int i = 0; i < 4; i++) {
        int submask = 0;
        for (int j = 7; j >= 0; j--) {
            submask += static_cast<int>(std::pow(2, j));
            if (submask == networkMask[i] || networkMask[i] == 0) {
                break;
            }
            else if (submask > networkMask[i]) {
                throw std::runtime_error("Invalid network mask: " + fullMask);
            }
        }
        if (submask != 255) {
            for (int k = i+1; k < 4; k++) {
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