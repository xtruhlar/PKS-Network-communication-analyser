# PKS-Network-communication-analyser

Design and implement Ethernet network analyser for network communications recorded in .pcap file and provides the following information about the communications. A fully developed assignment fulfils the following tasks:
1.	A listing of all frames in hexadecimal form sequentially as they were recorded in the file. .
For each frame, output should state:
a.	Sequence number of the frame in the parsed file. 
b.	The length of the frame in bytes provided by the pcap API, as well as the length of this frame carried over the medium. 
c.	Frame type - Ethernet II, IEEE 802.3 with LLC, IEEE 802.3 with LLC and SNAP, IEEE 802.3 - Raw.
d.	For IEEE 802.3 with LLC, also indicate the Service Access Point (SAP), e.g. STP, CDP, IPX, SAP...
e.	For IEEE 802.3 with LLC and SNAP, also indicate PID, e.g. AppleTalk, CDP, DTP ...
f.	The source and destination physical (MAC) addresses of the nodes between which the frame was transmitted.
g.	In the output, the frame 16 bytes per line.. Each line is terminated by a newline character. For the clarity of the output, it is recommended to use a non-proportional (monospace) font.
h.	The output must be in YAML. You should use Ruamel for Python.
2.	List of IP addresses and encapsulated protocol on layer 2-4 for Ethernet II frames.
a.	Encapsulated protocol in frame header. (ARP, IPv4, IPv6 .... )
b.	Source and destination IP address of the packet.
c.	For IPv4, also specify the encapsulated protocol. (TCP, UDP...)
d.	For the 4th layer i.e., TCP and UDP, indicate the source and destination port of the communication and if one of the ports is among the "well-known ports", also Include the name of the application protocol. Note that the IP header can range in size from 20B to 60B.
e.	Protocol numbers within Ethernet II (Ethertype field), in IP packet (Protocol field) and port numbers for transport protocols must be read from one or more external text files (Task 2 points a, c, and d). Example of possible external file formatting is at the end of this document.
f.	Output also names in addition to numbers for well-known protocols and ports (at minimum for the protocols listed in tasks 1) and 2). The program shall output name of encapsulated protocol previously unknown protocol after its name and protocol (or port) number are added to the external file.
g.	A library file used by the program is not considered an external file.
3.	Provide the following statistics for IPv4 packets at the end of output from task 2:
a.	A list of IP addresses of all sending nodes and number of packets each sent.
b.	The IP address of the node that sent (regardless of the recipient) the most packets, and number of packets. If there are more that sent the most, list them all.

Your program with communication analysis for selected protocols:
Pre-preparation:
a.	Implement the -p (as protocol) CLI option, which will be followed by another argument, namely the abbreviation of the protocol taken from the external file, e.g. analyzer.py -p HTTP. If the option is followed by any argument or the specified argument is a non-existent protocol, the program will print an error message and return to the beginning. Alternatively, a menu can be implemented, but the output must be written to a YAML file.
b.	The output of each frame in the following filters must also meet the requirements set in Tasks 1 and 2 (L2 and L3 analysis). If the argument following "-p" option specifies connection-oriented protocol communication (i.e. encapsulated in TCP):
c.	List all complete communications with their order number. Complete communication must include establishment (SYN) and termination (FIN on both sides; or FIN and RST; or RST only) of the connection. There are two ways for opening and four ways for closing a complete communication.
d.	List the first incomplete communication that contains only the connection establishment or only termination.
e.	Your analyser must support the following connection-oriented protocols: HTTP, HTTPS, TELNET, SSH, FTP radiation, FTP data.

If the argument following "-p" option specifies connectionless protocol (over UDP):
f)	For the FTP protocol list all frames and clearly list them in communications, not only the first frame on UDP port 69, but identify all frames for each TFTP communication and clearly show which frames belong to which communication. We consider a complete TFTP communication to be one where the size of the last datagram with data is smaller than the agreed block size when the connection is established, and at the same time the sender of this packet receives an ACK from the other side. See chapters: TFTP General and TFTP Detailed Operation.

If the argument following "-p" option specifies ICMP protocol:
g)	The program identifies all types of ICMP messages. Split the Echo request and Echo reply (including Time exceeded) into complete communications based on the following principle. First, you need to identify the source and destination IP pairs that exchanged ICMP messages and associate each pair with their ICMP messages. Echo request and Echo reply contain fields Identifier a Sequence in the header. The Identifier field indicates the communication number within the IP address pair and the Sequence field indicates the sequence number within the communication. Both fields can be the same for different IP source and IP destination pairs. This implies that the new communication is identified by the IP address pair and the ICMP field Identifier. All other ICMP message types and ICMP Echo request/reply messages without a pair will be output as incomplete communications.
h)	For each ICMP frame, also indicate the ICMP message type Type field in the ICMP header), e.g. Echo request, Echo reply, Time exceeded, etc. For complete communications, also list the ICMP fields Identifier and Sequence.

If the argument following "-p" option specifies ARP protocol:
i)	List all ARP pairs (request – reply), also indicate the IP address for which the MAC address is being sought, for Reply indicate a specific pair - IP address and MAC address found. If multiple ARP-Request frames were sent to the same IP address, first identify all ARP pairs and list them in one complete communication, regardless of the source address of the ARP-Request. If there are ARP-Requests frames without ARP-Reply, list them all in one incomplete communication. Likewise, if it identifies more ARP reply than ARP request messages to the same IP, then list all ARP reply without ARP request in one incomplete communication. Ignore other types of ARP messages within the filter.

If the IP packet is fragmented:
j)	If the size of the IP packet exceeds the MTU, the packet is split into several smaller packets called fragments before being sent and then the whole message is reassembled after receiving all the fragments on the receiver's side. For ICMP filter, identify all fragmented IP packets and list for each such packet all frames with its fragments in the correct order. For fragment merging, study the fields Identification, Flags and Fragment Offset in the IP header and include them also for packets in such communication that contain fragmented packets as id, flags_mf and frag_offset, more details HERE. The task is just an extension of the ICMP filter task, so the input argument for the protocol is same.

The solution must include documentation:

a.	Clarity and comprehensibility of the submitted documentation are required in addition to the overall solution quality. Full marks are awarded only for documents that provide all the essentials about the functioning of their program. This includes the processing diagram *.pcap files and a description of individual parts of the source code (libraries, classes, methods, etc.).
b.	Documentation shall comprise: >- Title page, >- Diagram (activity, flowchart) of processing (concept) and operation of the program, >- The proposed mechanism for protocol analysis on individual layers, >- An example of the structure of external files for specifying protocols and ports, >- Annotated user interface, >- Chosen implementation environment, >- Evaluation and possible extensions.
