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
	anayzeMode := flag.Bool("A", false, "Analyze mode. This option allows you to see NBT-NS, BROWSER, LLMNR requests without responding. (default false)")
	flag.Parse()

	if *intface == "" {
		usage()
		flag.PrintDefaults()
		fmt.Println("You must specify an interaface to use")
		os.Exit(1)
	}

	var IPADDRESS net.IP
	var MAC net.HardwareAddr

	if *ipaddress == "" {
		// Get IP address of the interface
		IPADDRESS = helpers.GetIP4(*intface)
		if IPADDRESS == nil {
			log.Fatal("Error getting IP address")
		}

		// Get mac address of the interface
		MAC = helpers.GetMac(*intface)
		if MAC == nil {
			log.Fatal("Error getting Mac address")
		}
	}

	helpers.Capture(*intface, IPADDRESS, MAC, *anayzeMode)
}
