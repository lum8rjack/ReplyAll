package helpers

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/google/gopacket/pcap"
)

func GetMac(device string) net.HardwareAddr {
	var hw net.HardwareAddr
	hw = nil

	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal("error with interfaces")
	}

	for _, iface := range ifaces {
		if iface.Name == device {
			return iface.HardwareAddr
		}
	}
	return hw
}

// Returns IPv4 address of the specified device
func GetIP4(device string) net.IP {
	var ip net.IP
	ip = nil

	// If nil then we need to set it
	if IPADDRESS == nil {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			return ip
		}

		for _, d := range devices {
			if d.Name == device {
				for _, address := range d.Addresses {
					ip = address.IP.To4()
					if ip != nil {
						return ip
					}
				}
			}
		}
	}

	return ip
}

// Returns IPv4 address of the specified device
func GetIP6(device string) net.IP {
	var ip net.IP
	ip = nil

	// If nil then we need to set it
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return ip
	}

	for _, d := range devices {
		if d.Name == device {
			for _, address := range d.Addresses {
				ip = address.IP
				if strings.Contains(ip.String(), ":") {
					return ip
				}
			}
		}
	}

	return ip
}

// Print all devices and their details
func PrintAllDevices() error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		e := fmt.Sprintf("Error getting all devices")
		return errors.New(e)
	}

	// Print device information
	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Printf("Name: %s\n", device.Name)
		mac := GetMac(device.Name)
		fmt.Printf("MAC: %s\n", mac)
		fmt.Println("Devices addresses: ")
		for _, address := range device.Addresses {
			fmt.Printf("- IP address: %s\n", address.IP)
			fmt.Printf("- Subnet mask: %s\n", address.Netmask)
		}
	}

	return nil
}
