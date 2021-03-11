// Minqi Shi
// 111548035
// References:
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

// packet_number := 0

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"os"
	"strings"
)

func tcp_flags(tcp *layers.TCP) string{
	s := ""
	// FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
	if tcp.FIN {s+= " FIN"}
	if tcp.SYN {s+= " SYN"}
	if tcp.RST {s+= " RST"}
	if tcp.PSH {s+= " PSH"}
	if tcp.ACK {s+= " ACK"}
	if tcp.URG {s+= " URG"}
	if tcp.ECE {s+= " ECE"}
	if tcp.CWR {s+= " CWR"}
	if tcp.NS {s+= " NS"}
	return s
}

func ethernet_type_convert(et layers.EthernetType) string{
	// https://pkg.go.dev/github.com/notti/gopacket/layers#EthernetType
	const (
		// EthernetTypeLLC is not an actual ethernet type.  It is instead a
		// placeholder we use in Ethernet frames that use the 802.3 standard of
		// srcmac|dstmac|length|LLC instead of srcmac|dstmac|ethertype.
		EthernetTypeLLC                         layers.EthernetType = 0
		EthernetTypeIPv4                        layers.EthernetType = 0x0800
		EthernetTypeARP                         layers.EthernetType = 0x0806
		EthernetTypeIPv6                        layers.EthernetType = 0x86DD
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
	if et == EthernetTypeLLC{
		return "0x0000"
	}else if et == EthernetTypeIPv4{
		return "0x0800"
	}else if et == EthernetTypeIPv6{
		return "0x86DD"
	}else if et == EthernetTypeARP{
		return "0x0806"
	}else {
		return "not found"
	}
}

// https://www.itread01.com/content/1546724723.html
func printPacketInfo(packet gopacket.Packet, dash_s string) {
	applicationLayer := packet.ApplicationLayer()
    if dash_s != "-1"{
        // fmt.Println("Application layer/Payload found.")
        // fmt.Printf("%s\n", applicationLayer.Payload())
		if applicationLayer == nil{
			return
		}
        // Search for a string inside the payload
        if !strings.Contains(string(applicationLayer.Payload()), dash_s) {
			// fmt.Println("AAAAAAAAAAAAAAAAAaa")
            return
        }
    }
	// Time
	fmt.Printf("%v",packet.Metadata().Timestamp.Format("2006-01-02 15:04:05.000000 "))


    // Let's see if the packet is an ethernet packet
    ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
    if ethernetLayer != nil {
        // fmt.Println("Ethernet layer detected.")
        ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
        fmt.Print(ethernetPacket.SrcMAC, " -> ")
        fmt.Print(ethernetPacket.DstMAC, " ")
        // Ethernet type is typically IPv4 but could be ARP or other
		hex_type := ethernet_type_convert(ethernetPacket.EthernetType)
        // fmt.Printf("type %T", ethernetPacket.EthernetType)
		// fmt.Print(packet[12:14])
		if hex_type == "not found"{
			fmt.Print("type ", ethernetPacket.EthernetType)
		}else{
        	fmt.Print("type ", hex_type)
		}
    }
	packet_length := packet.Metadata().CaptureInfo.Length
	fmt.Println(" len", packet_length)

    // Let's see if the packet is IP (even though the ether type told us)
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer != nil {
        // fmt.Println("IPv4 layer detected.")
        ip, _ := ipLayer.(*layers.IPv4)

        // IP layer variables:
        // Version (Either 4 or 6)
        // IHL (IP Header Length in 32-bit words)
        // TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
        // Checksum, SrcIP, DstIP

		    // Let's see if the packet is TCP
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		udplayer := packet.Layer(layers.LayerTypeUDP)
		// var(
		// 	isTCP := false
		// 	isUDP := false
		// )
		if tcpLayer != nil {
			// fmt.Println("TCP layer detected.")
			tcp, _ := tcpLayer.(*layers.TCP)
			// tcp := tcpLayer
			// fmt.Println(reflect.TypeOf(tcp), reflect.TypeOf(tcpLayer))
			// // fmt.Println(tcpLayer)
			// fmt.Println("some=", some)

			// TCP layer variables:
			// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
			// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
			// fmt.Printf("From port %d to %d\n", tcpLayer.SrcPort, tcpLayer.DstPort)
			// fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
			// fmt.Println("Sequence number: ", tcp.Seq)
			// fmt.Println()
			fmt.Printf("%s.%s -> %s.%s", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
			fmt.Print(" ", ip.Protocol)
			fmt.Print(tcp_flags(tcp))
		}else if udplayer != nil {
			udp, _ := udplayer.(*layers.UDP)
			fmt.Printf("%s.%s -> %s.%s", ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort)
			fmt.Print(" ", ip.Protocol)
		}else{
			fmt.Printf("%s -> %s", ip.SrcIP, ip.DstIP)
			fmt.Print(" ", ip.Protocol)
		}
		fmt.Println()
    }

    // Iterate over all layers, printing out each layer type
    // fmt.Println("All packet layers:")
    // for _, layer := range packet.Layers() {
    //     fmt.Println("- ", layer.LayerType())
    // }

    // When iterating through packet.Layers() above,
    // if it lists Payload layer then that is the same as
    // this applicationLayer. applicationLayer contains the payload
	if applicationLayer != nil {
        fmt.Printf("%s\n", applicationLayer.Payload())
    }
	
    // Check for errors
    if err := packet.ErrorLayer(); err != nil {
        fmt.Println("Error decoding some part of the packet:", err)
    }

	fmt.Println("----------------------------------------------")
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

	fmt.Printf("Argument vector: %v\n", argv)
	fmt.Printf("Vector Length: %v\n", argv_length)

	var (
		inter_face  string = "-1"
		filepath    string = "-1"
		str         string = "-1"
		expr        []string
		expr_string string
		optind      int = 0
	)

	// if argv_length == 0 {
	// 	fmt.Println("Missing arguments!")
	// 	return
	// }

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
			fmt.Println("Interface:", inter_face)
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
			fmt.Println("File:", filepath)
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
			fmt.Println("String:", str)
		default:
			fmt.Println("Unrecognized command!")
			return
		}
	}
	// if argv_length != 0 && argv_length%2 != 0 {
	// 	expr = argv[argv_length-1]
	// 	fmt.Println("Expr:", expr)
	// }
	// optind = optind - 2
	// fmt.Println(optind)
	if optind < argv_length {
		expr = argv[optind:]
		fmt.Printf("Expr: %v\n", expr)
	}
	if len(expr) != 0 {
		for i := 0; i < len(expr); i++ {
			expr_string += expr[i]
			if i != len(expr)-1 {
				expr_string += " "
			}
		}
		fmt.Printf("Expr String: %v\n", expr_string)
	}else {
		expr_string = ""
	}
	//https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
	if inter_face == "-1"{
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
		} else if err := handle.SetBPFFilter(expr_string); err != nil {  // BPF
			panic(err)		
		} else {
			defer handle.Close()
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				// handlePacket(packet) // Do something with a packet here.
				// fmt.Printf("%T",packet)
				printPacketInfo(packet, str)
			}
		}
	// live cap
	} else {
		if handle, err := pcap.OpenLive(inter_face, 1600, true, pcap.BlockForever); err != nil {
			panic(err)
		  } else if err := handle.SetBPFFilter(expr_string); err != nil {  // BPF
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
