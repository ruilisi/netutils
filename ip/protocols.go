package ip

import "fmt"

// IP Protocol Numbers (IANA assigned)
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
const (
	ProtoHOPOPT         uint8 = 0   // IPv6 Hop-by-Hop Option
	ProtoICMP           uint8 = 1   // Internet Control Message Protocol
	ProtoIGMP           uint8 = 2   // Internet Group Management Protocol
	ProtoGGP            uint8 = 3   // Gateway-to-Gateway Protocol
	ProtoIPv4           uint8 = 4   // IPv4 encapsulation
	ProtoST             uint8 = 5   // Stream
	ProtoTCP            uint8 = 6   // Transmission Control Protocol
	ProtoCBT            uint8 = 7   // CBT
	ProtoEGP            uint8 = 8   // Exterior Gateway Protocol
	ProtoIGP            uint8 = 9   // any private interior gateway (used by Cisco for their IGRP)
	ProtoBBNRCCMON      uint8 = 10  // BBN RCC Monitoring
	ProtoNVPII          uint8 = 11  // Network Voice Protocol
	ProtoPUP            uint8 = 12  // PUP
	ProtoARGUS          uint8 = 13  // ARGUS
	ProtoEMCON          uint8 = 14  // EMCON
	ProtoXNET           uint8 = 15  // Cross Net Debugger
	ProtoCHAOS          uint8 = 16  // Chaos
	ProtoUDP            uint8 = 17  // User Datagram Protocol
	ProtoMUX            uint8 = 18  // Multiplexing
	ProtoDCNMEAS        uint8 = 19  // DCN Measurement Subsystems
	ProtoHMP            uint8 = 20  // Host Monitoring Protocol
	ProtoPRM            uint8 = 21  // Packet Radio Measurement
	ProtoXNSIDP         uint8 = 22  // XEROX NS IDP
	ProtoTRUNK1         uint8 = 23  // Trunk-1
	ProtoTRUNK2         uint8 = 24  // Trunk-2
	ProtoLEAF1          uint8 = 25  // Leaf-1
	ProtoLEAF2          uint8 = 26  // Leaf-2
	ProtoRDP            uint8 = 27  // Reliable Data Protocol
	ProtoIRTP           uint8 = 28  // Internet Reliable Transaction Protocol
	ProtoISOTP4         uint8 = 29  // ISO Transport Protocol Class 4
	ProtoNETBLT         uint8 = 30  // Bulk Data Transfer Protocol
	ProtoMFENSP         uint8 = 31  // MFE Network Services Protocol
	ProtoMERITINP       uint8 = 32  // MERIT Internodal Protocol
	ProtoDCCP           uint8 = 33  // Datagram Congestion Control Protocol
	Proto3PC            uint8 = 34  // Third Party Connect Protocol
	ProtoIDPR           uint8 = 35  // Inter-Domain Policy Routing Protocol
	ProtoXTP            uint8 = 36  // XTP
	ProtoDDP            uint8 = 37  // Datagram Delivery Protocol
	ProtoIDPRCMTP       uint8 = 38  // IDPR Control Message Transport Protocol
	ProtoTPPP           uint8 = 39  // TP++ Transport Protocol
	ProtoIL             uint8 = 40  // IL Transport Protocol
	ProtoIPv6           uint8 = 41  // IPv6 encapsulation
	ProtoSDRP           uint8 = 42  // Source Demand Routing Protocol
	ProtoIPv6Route      uint8 = 43  // Routing Header for IPv6
	ProtoIPv6Frag       uint8 = 44  // Fragment Header for IPv6
	ProtoIDRP           uint8 = 45  // Inter-Domain Routing Protocol
	ProtoRSVP           uint8 = 46  // Resource Reservation Protocol
	ProtoGRE            uint8 = 47  // Generic Routing Encapsulation
	ProtoDSR            uint8 = 48  // Dynamic Source Routing Protocol
	ProtoBNA            uint8 = 49  // BNA
	ProtoESP            uint8 = 50  // Encapsulating Security Payload
	ProtoAH             uint8 = 51  // Authentication Header
	ProtoINLSP          uint8 = 52  // Integrated Net Layer Security Protocol
	ProtoSWIPE          uint8 = 53  // IP with Encryption
	ProtoNARP           uint8 = 54  // NBMA Address Resolution Protocol
	ProtoMOBILE         uint8 = 55  // IP Mobility
	ProtoTLSP           uint8 = 56  // Transport Layer Security Protocol
	ProtoSKIP           uint8 = 57  // SKIP
	ProtoIPv6ICMP       uint8 = 58  // ICMP for IPv6
	ProtoIPv6NoNxt      uint8 = 59  // No Next Header for IPv6
	ProtoIPv6Opts       uint8 = 60  // Destination Options for IPv6
	ProtoAHIP           uint8 = 61  // any host internal protocol
	ProtoCFTP           uint8 = 62  // CFTP
	ProtoALN            uint8 = 63  // any local network
	ProtoSATEXPAK       uint8 = 64  // SATNET and Backroom EXPAK
	ProtoKRYPTOLAN      uint8 = 65  // Kryptolan
	ProtoRVD            uint8 = 66  // MIT Remote Virtual Disk Protocol
	ProtoIPPC           uint8 = 67  // Internet Pluribus Packet Core
	ProtoADFS           uint8 = 68  // any distributed file system
	ProtoSATMON         uint8 = 69  // SATNET Monitoring
	ProtoVISA           uint8 = 70  // VISA Protocol
	ProtoIPCV           uint8 = 71  // Internet Packet Core Utility
	ProtoCPNX           uint8 = 72  // Computer Protocol Network Executive
	ProtoCPHB           uint8 = 73  // Computer Protocol Heart Beat
	ProtoWSN            uint8 = 74  // Wang Span Network
	ProtoPVP            uint8 = 75  // Packet Video Protocol
	ProtoBRSATMON       uint8 = 76  // Backroom SATNET Monitoring
	ProtoSUNND          uint8 = 77  // SUN ND PROTOCOL-Temporary
	ProtoWBMON          uint8 = 78  // WIDEBAND Monitoring
	ProtoWBEXPAK        uint8 = 79  // WIDEBAND EXPAK
	ProtoISOIP          uint8 = 80  // ISO Internet Protocol
	ProtoVMTP           uint8 = 81  // VMTP
	ProtoSECUREVMTP     uint8 = 82  // SECURE-VMTP
	ProtoVINES          uint8 = 83  // VINES
	ProtoTTP            uint8 = 84  // Transaction Transport Protocol
	ProtoIPTM           uint8 = 84  // Internet Protocol Traffic Manager
	ProtoNSFNETIGP      uint8 = 85  // NSFNET-IGP
	ProtoDGP            uint8 = 86  // Dissimilar Gateway Protocol
	ProtoTCF            uint8 = 87  // TCF
	ProtoEIGRP          uint8 = 88  // EIGRP
	ProtoOSPFIGP        uint8 = 89  // OSPFIGP
	ProtoSpriteRPC      uint8 = 90  // Sprite RPC Protocol
	ProtoLARP           uint8 = 91  // Locus Address Resolution Protocol
	ProtoMTP            uint8 = 92  // Multicast Transport Protocol
	ProtoAX25           uint8 = 93  // AX.25 Frames
	ProtoIPIP           uint8 = 94  // IP-within-IP Encapsulation Protocol
	ProtoMICP           uint8 = 95  // Mobile Internetworking Control Protocol
	ProtoSCCSP          uint8 = 96  // Semaphore Communications Sec. Protocol
	ProtoETHERIP        uint8 = 97  // Ethernet-within-IP Encapsulation
	ProtoENCAP          uint8 = 98  // Encapsulation Header
	ProtoAPES           uint8 = 99  // any private encryption scheme
	ProtoGMTP           uint8 = 100 // GMTP
	ProtoIFMP           uint8 = 101 // Ipsilon Flow Management Protocol
	ProtoPNNI           uint8 = 102 // PNNI over IP
	ProtoPIM            uint8 = 103 // Protocol Independent Multicast
	ProtoARIS           uint8 = 104 // ARIS
	ProtoSCPS           uint8 = 105 // SCPS
	ProtoQNX            uint8 = 106 // QNX
	ProtoAN             uint8 = 107 // Active Networks
	ProtoIPComp         uint8 = 108 // IP Payload Compression Protocol
	ProtoSNP            uint8 = 109 // Sitara Networks Protocol
	ProtoCompaqPeer     uint8 = 110 // Compaq Peer Protocol
	ProtoIPXinIP        uint8 = 111 // IPX in IP
	ProtoVRRP           uint8 = 112 // Virtual Router Redundancy Protocol
	ProtoPGM            uint8 = 113 // PGM Reliable Transport Protocol
	ProtoA0HOP          uint8 = 114 // any 0-hop protocol
	ProtoL2TP           uint8 = 115 // Layer Two Tunneling Protocol
	ProtoDDX            uint8 = 116 // D-II Data Exchange (DDX)
	ProtoIATP           uint8 = 117 // Interactive Agent Transfer Protocol
	ProtoSTP            uint8 = 118 // Schedule Transfer Protocol
	ProtoSRP            uint8 = 119 // SpectraLink Radio Protocol
	ProtoUTI            uint8 = 120 // UTI
	ProtoSMP            uint8 = 121 // Simple Message Protocol
	ProtoSM             uint8 = 122 // Simple Multicast Protocol
	ProtoPTP            uint8 = 123 // Performance Transparency Protocol
	ProtoISIS           uint8 = 124 // ISIS over IPv4
	ProtoFIRE           uint8 = 125 // FIRE
	ProtoCRTP           uint8 = 126 // Combat Radio Transport Protocol
	ProtoCRUDP          uint8 = 127 // Combat Radio User Datagram
	ProtoSSCOPMCE       uint8 = 128 // SSCOPMCE
	ProtoIPLT           uint8 = 129 // IPLT
	ProtoSPS            uint8 = 130 // Secure Packet Shield
	ProtoPIPE           uint8 = 131 // Private IP Encapsulation within IP
	ProtoSCTP           uint8 = 132 // Stream Control Transmission Protocol
	ProtoFC             uint8 = 133 // Fibre Channel
	ProtoRSVPE2EIGNORE  uint8 = 134 // RSVP-E2E-IGNORE
	ProtoMobilityHeader uint8 = 135 // Mobility Header
	ProtoUDPLite        uint8 = 136 // UDPLite
	ProtoMPLSinIP       uint8 = 137 // MPLS-in-IP
	ProtoMANET          uint8 = 138 // MANET Protocols
	ProtoHIP            uint8 = 139 // Host Identity Protocol
	ProtoShim6          uint8 = 140 // Shim6 Protocol
	ProtoWESP           uint8 = 141 // Wrapped Encapsulating Security Payload
	ProtoROHC           uint8 = 142 // Robust Header Compression
	ProtoEthernet       uint8 = 143 // Ethernet
	ProtoAGGFRAG        uint8 = 144 // AGGFRAG encapsulation payload
	ProtoNSH            uint8 = 145 // Network Service Header
	// 146-252: Unassigned
	ProtoReserved253 uint8 = 253 // Use for experimentation and testing
	ProtoReserved254 uint8 = 254 // Use for experimentation and testing
	ProtoReserved    uint8 = 255 // Reserved
)

// protoNames maps common protocol numbers to short names for logging.
var protoNames = map[uint8]string{
	ProtoHOPOPT:    "HOPOPT",
	ProtoICMP:      "ICMP",
	ProtoIGMP:      "IGMP",
	ProtoIPv4:      "IPv4",
	ProtoTCP:       "TCP",
	ProtoUDP:       "UDP",
	ProtoIPv6:      "IPv6",
	ProtoIPv6Route: "IPv6-Route",
	ProtoIPv6Frag:  "IPv6-Frag",
	ProtoGRE:       "GRE",
	ProtoESP:       "ESP",
	ProtoAH:        "AH",
	ProtoIPv6ICMP:  "ICMPv6",
	ProtoIPv6NoNxt: "IPv6-NoNxt",
	ProtoIPv6Opts:  "IPv6-Opts",
	ProtoSCTP:      "SCTP",
}

// ProtoName returns a human-readable name for the given IP protocol number.
// Returns the short name for common protocols, or the decimal number for others.
func ProtoName(proto uint8) string {
	if name, ok := protoNames[proto]; ok {
		return name
	}
	return fmt.Sprintf("%d", proto)
}
