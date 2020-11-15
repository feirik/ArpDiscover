### Background
The purpose of the program is to discover hosts broadcasting ARP packets on Windows 10. The program passively sniffs packets and cannot verify that the packets are received as the interface on Windows 10 is likely not in monitor mode.

![Example output](https://github.com/feirik/ArpMonitor/blob/master/Images/ArpDiscover_readme.png)

### Command line options

#### -i --interface <INTERFACE IP ADDRESS> (optional)
Selects an interface to scan. If not specified, the program will attempt to scan likely interfaces and select the most active interface recieving ARP packets.

### ARP packet sniffing
The program works by sniffing arp packets using Winpcap. This is done through a callback function filtering ARP packets every time new network packet(s) are detected. The program is limited to sniffing maximum 2 ARP packets per sniffing event as the data structure is sent into the callback function. The captured ARP packets are processed and the data for the discovered hosts is shown in the command line output.  

### Data sources
An Organizationally unique identifier (OUI) list is used for showing the manufacturer connected to a MAC address.








