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

package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	// fmt.Println("Hello world!")
	argv := os.Args[1:]      // Argument vector
	argv_length := len(argv) // Length of the arguments

	fmt.Printf("Argument vector: %v\n", argv)
	fmt.Printf("Vector Length: %v\n", argv_length)

	var (
		inter_face string = "-1"
		filepath   string = "-1"
		str        string = "-1"
		expr       []string
		optind     int = 0
	)

	// if argv_length == 0 {
	// 	fmt.Println("Missing arguments!")
	// 	return
	// }

	for i := 0; i < argv_length; i = i + 2 {
		opt := argv[i]
		if !strings.Contains(opt, "-") {
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
	fmt.Println(optind)
	if optind < argv_length {
		expr = argv[optind:]
		fmt.Printf("Expr: %v\n", expr)
	}

}
