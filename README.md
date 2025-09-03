# Matter_Sigma_Filter Documentation
## Description

**Matter_Sigma_Filter** is a program for capturing and processing network traffic, specifically focusing on the 
CASE Sigma protocol. Sigma1 refers to the first message in the protocol. The program counts packets per MAC address 
pair and automatically blocks any MAC address pair that exceeds a configurable threshold using ```ebtables```. 
It supports both live network interface monitoring and offline pcap file analysis.

## Main Features

- Captures and processes network traffic on a specified interface or from a pcap file
- Filters and processes Matter / CASE Sigma1 packets
- Counts packets per MAC address pair within a time window
- Automatically blocks MAC address pairs with excessive traffic using ```ebtables```
- Suppresses output and logging for blocked pairs
- Provides detailed logs and per-window statistics
  
## Dependencies

- ```libpcap``` development package
- ```ebtables``` tool (must be installed)
- Root privileges (required for ```ebtables```)

## Installation

Build with the provided Makefile:

```
$ make
```

## Usage
Typical usage:
Run the program as root to capture and filter CASE Sigma1 packets on a network interface or from a pcap file. 
The program will block MAC address pairs that exceed the packet threshold.
```
./matter_sigma_filter interface <interface_name>
./matter_sigma_filter file <pcap_file>
```

## Example
Example use case:
To monitor live traffic on the ```wlo1``` interface and block MAC address pairs with excessive Sigma1 packets:
```
# ./matter_sigma_filter interface wlo1
```
A more detailed example:
Suppose you want to analyze a pcap file named ```capture.pcap``` for Sigma1 traffic and block offending MAC address pairs:
```
# ./matter_sigma_filter file capture.pcap
```

## Command Line Arguments
- `interface <name>`: Monitor live traffic on the specified network interface
- `file <filename>`: Analyze packets from a pcap file
  
## Output
- Prints per-window statistics for MAC address pairs and packet counts
- On blocking:
```
BLOCKED: <source MAC> -> <destination MAC>
```
- Log file contains detailed packet information

## Developer Information
- Written in C, modular structure
- Packet processing uses the ```packet_info_t``` structure
- Blocking is performed per MAC address pair using ```ebtables``` rules
