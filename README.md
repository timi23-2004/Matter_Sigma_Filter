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

## Building

Build the program with the provided Makefile:

```
$ make
```

## Usage
Typical usage:
Run the program as `root` to capture and filter CASE Sigma1 packets on a network interface or from a pcap file. 
The program will block MAC address pairs packet number threshold.
```
./matter_sigma_filter interface <interface_name>
./matter_sigma_filter file <pcap_file>
```

## Example
Example use case:
To monitor live traffic on the ```wlo1``` interface and block MAC address pairs with an excessive number of Sigma1 packets:
```
$ ./matter_sigma_filter interface wlo1
```
More detailed example:
Suppose you want to analyze a pcap file named `capture.pcap` for Sigma1 traffic and block any MAC address pairs that exceed the packet threshold:
```
$ ./matter_sigma_filter file capture.pcap
```

## Command Line Arguments
- `interface <name>`: Monitor live traffic on the specified network interface
- `file <filename>`: Analyze packets from a pcap file
  
## Output

Example output:

```
Captured a packet with length: 136
Source MAC: ac:de:48:00:55:66
Destination MAC: ac:de:48:00:77:88
UDP Source Port: 5540
UDP Destination Port: 5540
IPv6 Source: fe80::1898:969a:bcb8:6235
IPv6 Destination: fe80::8ebc:7bef:fe48:a61e
message flags: 0x04
session id: 0x0000
security flags: 0x00
message counter: 0xb6058b0a
source node id: 0x87e7d9ea7ecf98b0
destination node id: (not present)
protocol opcode: 0x30

Packet count for ac:de:48:00:55:66 -> ac:de:48:00:77:88 reached maximum threshold of 100
cmd: ebtables -A FORWARD -s ac:de:48:00:55:66 -d ac:de:48:00:77:88 -j DROP
BLOCKED: ac:de:48:00:55:66 -> ac:de:48:00:77:88

Packet counts per MAC pair in this window:
ac:de:48:00:11:22 -> ac:de:48:00:33:44 : 12 pcs
ac:de:48:00:55:66 -> ac:de:48:00:77:88 : 100 pcs
```

The generated log file contains detailed packet information, for example:

```
2025-09-04 12:34:56 | ac:de:48:00:11:22 -> ac:de:48:00:33:44 | UDP | Length | Ports | IPV6 |
```

## License

This project is licensed under the GNU General Public License v3.0.
See the [LICENSE](LICENSE) file for details.
