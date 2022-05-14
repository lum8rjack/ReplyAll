package helpers

import (
	"ReplyAll/poisoners"
	"log"
	"net"
	"time"

	"github.com/google/gopacket/pcap"
)

const (
	SNAPSHOTLENGTH int32         = 65535            // Snapshot length
	PROMISCUOUS    bool          = false            // Promiscuous mode
	TIMEOUT        time.Duration = -1 * time.Second // Timeout
)

var (
	IPADDRESS net.IP = nil // Keep track of IP of the device we set
)

func Capture(device string, ip net.IP, mac net.HardwareAddr, analyze bool) {
	// Create a handle for each parser/poisoner
	// Listen on the provided interface
	handle, err := pcap.OpenLive(device, SNAPSHOTLENGTH, PROMISCUOUS, TIMEOUT)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Listen on the provided interface
	handle2, err := pcap.OpenLive(device, SNAPSHOTLENGTH, PROMISCUOUS, TIMEOUT)
	if err != nil {
		log.Fatal(err)
	}
	defer handle2.Close()

	// Listen on the provided interface
	handle3, err := pcap.OpenLive(device, SNAPSHOTLENGTH, PROMISCUOUS, TIMEOUT)
	if err != nil {
		log.Fatal(err)
	}
	defer handle3.Close()

	// Check if we are only analyzing and not poisoning
	if analyze {
		log.Printf("[Analyze mode] ReplyAll started listener on %s\n", device)

	} else {
		log.Printf("[Poison mode] ReplyAll started listener on %s and responding with IP of %s\n", device, ip)
	}

	// Start LLMNR capture/poison
	go poisoners.StartLLMNR(handle, ip, mac, analyze)

	// Start MDNS capture/poison
	go poisoners.StartMDNS(handle2, ip, mac, analyze)

	// Start NBNS capture/poisoner
	poisoners.StartNBNS(handle3, ip, mac, analyze)
}
