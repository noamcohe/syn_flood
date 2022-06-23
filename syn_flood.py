"""
Exercise Syn-Flood
Author: Noam Cohen
Purpose: write a simple plan, that find attackers according to the amount of SYN asks without ACK.
Note: I chose to find the attackers,
      by having all the IP addresses that sent more than three SYN asks, without ACK.
"""


# Import modules:
from scapy.all import *
from scapy.layers.inet import IP, TCP


# Constants:
FILE_NAME = "C:\\Networks\\work\\SynFloodSample.pcap"
SUSPECT_FILE = "C:\\Networks\\work\\suspect.txt"


def check_ip(pcapFile):
    """
    This function, create a dictionary that will contain all the IP addresses in the pcap file,
    and for each IP address (keys), their value will be amount of occurrences,
    that they sent SYN flag without ACK flag.
    """
    # Dictionary for the ip addresses:
    suspected_ip = {}

    # Pass on all the packets in the pcap file:
    for pkt in pcapFile:
        if IP in pkt:
            # If it is the first time we Encountered this IP address:
            if pkt[IP].src not in suspected_ip:
                # Then we put in out dictionary this IP address, and initializing her value to zero(0):
                suspected_ip[pkt[IP].src] = 0

            # if only the SYN flag is on:
            if pkt[TCP].flags == 'S':
                # Then increase by one:
                suspected_ip[pkt[IP].src] += 1

            # Else, if ACK flag is on:
            elif pkt[TCP].flags == 'A':
                # If the amount of SYN occurrences is not zero:
                if suspected_ip[pkt[IP].src] != 0:
                    # Then decrease by one:
                    suspected_ip[pkt[IP].src] -= 1

    return suspected_ip


def write_to_file(suspected_ip):
    """
    This function Run of all the dictionary keys,
    and write to 'suspect.txt' file all the suspect IP addresses (if they have more than 3 SYN without ACK).
    """
    # Open the txt file:
    with open(SUSPECT_FILE, 'a') as write_file:
        # The amount of occurrences that the client sent SYN without ACK:
        count = 0
        # Run of all the dictionary keys:
        for ip in suspected_ip:
            # If the occurrences of SYN without ACK is more than 3:
            if suspected_ip[ip] > 3:
                # Then increase count cy one:
                count += 1
                # Write this IP address to the file:
                write_file.write(ip + '\n')

    print(count)


def main():
    # The pcap file:
    pcapFile = rdpcap(FILE_NAME)

    # Call to 'check_ip' function, and send the pcap file:
    suspected_ip = check_ip(pcapFile)

    # Write to the file all the suspect IP addresses:
    write_to_file(suspected_ip)


if __name__ == "__main__":
    main()
