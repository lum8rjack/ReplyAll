package main

import (
	"ReplyAll/helpers"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
)

func usage() {
	fmt.Println("Usage: ReplyAll -interface eth0")
}

func main() {
	// Setup flags
	intface := flag.String("interface", "", "Network interface to use and listen on")
	ipaddress := flag.String("ip", "", "IP address to respond with (defaults to the IP of the interface you specify)")
	anayzeMode := flag.Bool("analyze", false, "Analyze mode. This option allows you to see NBT-NS, BROWSER, LLMNR requests without responding. (default false)")
	flag.Parse()

	if *intface == "" {
		usage()
		flag.PrintDefaults()
		fmt.Println("You must specify an interaface to use")
		os.Exit(0)
	}

	var IPADDRESS net.IP

	MAC := helpers.GetMac(*intface)

	if *ipaddress == "" {
		// Get IP address of the interface
		IPADDRESS = helpers.GetIP4(*intface)
		if IPADDRESS == nil {
			log.Fatalf("Error getting IP address of interface %s\n", *intface)
		}
	} else {
		IPADDRESS = net.ParseIP(*ipaddress)
		if IPADDRESS == nil {
			log.Fatalf("Error parsing IP address: %s\n", *ipaddress)
		}
	}

	helpers.Capture(*intface, IPADDRESS, MAC, *anayzeMode)
}
