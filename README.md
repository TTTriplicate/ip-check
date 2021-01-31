# Lab 1

## IP Addresses

Chris Sousa
CS-331

### How to run:
In the project, there is a file names `IP.dat`.  This is a raw text file, currently containing the test cases:
5 pairs of IP addresses and a corresponding network mask, separated by whitespace.  Either the 
contents of this file should be replaced, or the path to your preffered text file can be substituted 
in the `fstream` at the start of the program.

### What it does:
When run, the project will read that file and parse the data one line at a time, breaking each line 
into octets.  The octets are divided into sets, and sent to the correct assignment operators in the 
`IPCheck` class.  If the IP or network mask are malformed in some way, the program will throw
an exception indicating this, print that to the standard output, and move on to the next input.

If the IP address and network mask are both good, the program proceeds to the required analyses.  It prints the IP address, network mask, network mask class, network address, and if the network
is public or private.