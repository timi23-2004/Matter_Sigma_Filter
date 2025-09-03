# Matter_Sigma_Filter-Documentation
## Decription

Matter-Sigma-Filter is a network monitoring and filtering tool for Matter (Sigma 1) protocol UDP packets over IPv6.
The program counts packets per MAC address pair and automatically blocks any pair that exceeds a configurable 
threshold using ebtables. It supports both live network interface monitoring and offline pcap file analysis.

## Main Features

- Monitors network traffic on a specified interface or from a pcap file
- Detects and processes Matter/Sigma 1 protocol packets
- Counts packets per MAC address pair within a time window
- Automatically blocks MAC address pairs with excessive traffic using ebtables
- Suppresses output and logging for blocked pairs
- Provides detailed logs and per-window statistics

## Usage

```
./matter_sigma_filter interface <interface_name>
./matter_sigma1_filter file <pcap_file>
```

## Example

```
./matter_sigma_filter interface wlo1
```

## Command Line Arguments
- `interface <name>`: Monitor live traffic on the specified network interface
- `file <filename>`: Analyze packets from a pcap file
## Output
- Prints per-window statistics for MAC address pairs and packet counts
- On blocking: ```“BLOCKED: <source MAC> -> <destination MAC>”```
- Log file contains detailed packet information
## Dependencies
- Linux operating system
- Root privileges (required for ebtables)
- libpcap development package
- ebtables installed

## Installation

Build with the provided Makefile:

```
make
```

## Developer Information
- Written in C, modular structure
- Packet processing uses the packet_info_t structure
- Blocking is performed per MAC address pair using ebtables rules
