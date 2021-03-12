// Minqi Shi
// 111548035
// References:
// And there are other references in the code
// 	https://www.tcpdump.org/pcap.html
// 	https://www.tcpdump.org/index.html#documentation
// 	https://pkg.go.dev/github.com/google/gopacket/
// 	https://pkg.go.dev/github.com/google/gopacket/pcap
// 	https://golang.org/doc/
// 	https://golang.org/pkg/encoding/hex/#example_Dump
// 	https://gobyexample.com/
//  https://pkg.go.dev/github.com/google/gopacket@v1.1.19/pcap
//  https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func tcp_flags(tcp *layers.TCP) string {
	s := ""
	// FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
	if tcp.FIN {
		s += " FIN"
	}
	if tcp.SYN {
		s += " SYN"
	}
	if tcp.RST {
		s += " RST"
	}
	if tcp.PSH {
		s += " PSH"
	}
	if tcp.ACK {
		s += " ACK"
	}
	if tcp.URG {
		s += " URG"
	}
	if tcp.ECE {
		s += " ECE"
	}
	if tcp.CWR {
		s += " CWR"
	}
	if tcp.NS {
		s += " NS"
	}
	return s
}

func ethernet_type_convert(et layers.EthernetType) string {
	// https://pkg.go.dev/github.com/notti/gopacket/layers#EthernetType
	const (
		// EthernetTypeLLC is not an actual ethernet type.  It is instead a
		// placeholder we use in Ethernet frames that use the 802.3 standard of
		// srcmac|dstmac|length|LLC instead of srcmac|dstmac|ethertype.
		EthernetTypeLLC  layers.EthernetType = 0
		EthernetTypeIPv4 layers.EthernetType = 0x0800
		EthernetTypeARP  layers.EthernetType = 0x0806
		EthernetTypeIPv6 layers.EthernetType = 0x86DD
		// EthernetTypeCiscoDiscovery              EthernetType = 0x2000
		// EthernetTypeNortelDiscovery             EthernetType = 0x01a2
		// EthernetTypeTransparentEthernetBridging EthernetType = 0x6558
		// EthernetTypeDot1Q                       EthernetType = 0x8100
		// EthernetTypePPP                         EthernetType = 0x880b
		// EthernetTypePPPoEDiscovery              EthernetType = 0x8863
		// EthernetTypePPPoESession                EthernetType = 0x8864
		// EthernetTypeMPLSUnicast                 EthernetType = 0x8847
		// EthernetTypeMPLSMulticast               EthernetType = 0x8848
		// EthernetTypeEAPOL                       EthernetType = 0x888e
		// EthernetTypeQinQ                        EthernetType = 0x88a8
		// EthernetTypeLinkLayerDiscovery          EthernetType = 0x88cc
		// EthernetTypeEthernetCTP                 EthernetType = 0x9000
	)
	if et == EthernetTypeLLC {
		return "0x0000"
	} else if et == EthernetTypeIPv4 {
		return "0x0800"
	} else if et == EthernetTypeIPv6 {
		return "0x86DD"
	} else if et == EthernetTypeARP {
		return "0x0806"
	} else {
		return "not found"
	}
}

// The following function is inspired from the following link
// https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
func printPacketInfo(packet gopacket.Packet, dash_s string) {
	applicationLayer := packet.ApplicationLayer()
	if dash_s != "-1" {
		if applicationLayer == nil {
			return
		}
		// Search for a string inside the payload
		if !strings.Contains(string(applicationLayer.Payload()), dash_s) {
			return
		}
	}
	// Time
	fmt.Printf("%v", packet.Metadata().Timestamp.Format("2006-01-02 15:04:05.000000 "))

	// ethernet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Print(ethernetPacket.SrcMAC, " -> ")
		fmt.Print(ethernetPacket.DstMAC, " ")
		// Ethernet type is typically IPv4 but could be ARP or other
		hex_type := ethernet_type_convert(ethernetPacket.EthernetType)
		if hex_type == "not found" {
			fmt.Print("type ", ethernetPacket.EthernetType)
		} else {
			fmt.Print("type ", hex_type)
		}
	}

	// packet length
	packet_length := packet.Metadata().CaptureInfo.Length
	fmt.Println(" len", packet_length)

	// IP
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		// TCP or UDP
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		udplayer := packet.Layer(layers.LayerTypeUDP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			fmt.Printf("%s.%s -> %s.%s", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
			fmt.Print(" ", ip.Protocol)
			fmt.Print(tcp_flags(tcp))
		} else if udplayer != nil {
			udp, _ := udplayer.(*layers.UDP)
			fmt.Printf("%s.%s -> %s.%s", ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort)
			fmt.Print(" ", ip.Protocol)
		} else {
			fmt.Printf("%s -> %s", ip.SrcIP, ip.DstIP)
			fmt.Print(" ", ip.Protocol)
		}
		fmt.Println()
	}

	// print the payload
	if applicationLayer != nil {
		pl := gopacket.LayerDump(applicationLayer)
		pl = pl[strings.Index(pl, "\n")+1:]
		fmt.Print(pl)
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
	fmt.Println()
	// fmt.Println("----------------------------------------------")
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("", r)
		}
	}()
	// fmt.Println("Hello world!")
	argv := os.Args[1:]      // Argument vector
	argv_length := len(argv) // Length of the arguments

	// fmt.Printf("Argument vector: %v\n", argv)
	// fmt.Printf("Vector Length: %v\n", argv_length)

	var (
		inter_face  string = "-1"
		filepath    string = "-1"
		str         string = "-1"
		expr        []string
		expr_string string
		optind      int = 0
	)

	for i := 0; i < argv_length; i = i + 2 {
		var opt string = argv[i]
		if opt[0] != '-' {
			continue
		}
		optind += 2
		switch opt {
		case "-i":
			if inter_face != "-1" {
				fmt.Println("Multiple interfaces provided!")
				return
			}
			if i+1 == argv_length {
				fmt.Println("Missing arguments!")
				return
			}
			inter_face = argv[i+1]
			// fmt.Println("Interface:", inter_face)
		case "-r":
			if filepath != "-1" {
				fmt.Println("Multiple files provided!")
				return
			}
			if i+1 == argv_length {
				fmt.Println("Missing arguments!")
				return
			}
			filepath = argv[i+1]
			// fmt.Println("File:", filepath)
		case "-s":
			if str != "-1" {
				fmt.Println("Multiple expression defined!")
				return
			}
			if i+1 == argv_length {
				fmt.Println("Missing arguments!")
				return
			}
			str = argv[i+1]
			// fmt.Println("String:", str)
		default:
			fmt.Println("Unrecognized command!")
			return
		}
	}
	if optind < argv_length {
		expr = argv[optind:]
		// fmt.Printf("Expr: %v\n", expr)
	}
	if len(expr) != 0 {
		for i := 0; i < len(expr); i++ {
			expr_string += expr[i]
			if i != len(expr)-1 {
				expr_string += " "
			}
		}
		// fmt.Printf("Expr String: %v\n", expr_string)
	} else {
		expr_string = ""
	}
	//https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
	if inter_face == "-1" {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			panic(err)
		}
		inter_face = devices[0].Name
	}

	//https://pkg.go.dev/github.com/google/gopacket@v1.1.19/pcap
	if filepath != "-1" {
		if handle, err := pcap.OpenOffline(filepath); err != nil {
			panic(err)
		} else if err := handle.SetBPFFilter(expr_string); err != nil { // BPF
			panic(err)
		} else {
			defer handle.Close()
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				printPacketInfo(packet, str)
			}
		}
		// live cap
	} else {
		if handle, err := pcap.OpenLive(inter_face, 1600, true, pcap.BlockForever); err != nil {
			panic(err)
		} else if err := handle.SetBPFFilter(expr_string); err != nil { // BPF
			panic(err)
		} else {
			defer handle.Close()
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				printPacketInfo(packet, str)
			}
		}
	}

}
