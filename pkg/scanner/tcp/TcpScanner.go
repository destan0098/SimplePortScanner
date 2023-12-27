package PortScanner

import (
	"fmt"
	"github.com/TwiN/go-color"
	tcpports "github.com/destan0098/SimplePortScanner/internal/TcpPorts"
	"io/ioutil"
	"net"
	"strconv"
	"time"

	"strings"
	"sync"
)

type PortInfo struct {
	Port    string
	Status  string
	Service string
}

var ipresult = make(map[string][]PortInfo)
var counter int
var counterMu sync.Mutex

// TcpScannerNew Adjust the pool size as needed
func TcpScannerNew(ipadd, ip string, timeout int) (map[string][]PortInfo, string, int) {
	portInfo := PortInfo{}
	var serviceName string
	portstr := strings.Split(ipadd, ":")
	port := portstr[1]
	timeoutdur := time.Duration(timeout)

	conn, err := net.DialTimeout("tcp", ipadd, timeoutdur*time.Millisecond)
	if err == nil {
		defer func(conn net.Conn) {
			err = conn.Close()
			if err != nil {

			}
		}(conn)

		/////////////////
		_, err = conn.Write([]byte("hello\n"))
		if err != nil {
			// Skip if the TCP SYN fails
			recover()
		}
		response, err := ioutil.ReadAll(conn)
		if err != nil {
			// Skip if the response reading fails
			recover()
		}

		// Check the response for any service-specific information
		serviceDetails := parseResponse(response)

		// If service details are found, create a service object and add it to the map
		if serviceDetails != "" {
			//	fmt.Println(serviceDetails)
			//serviceName = strings.Split(string(serviceDetails[:4]), " ")[0]
			serviceName = serviceDetails
		}

		// Convert the response bytes to a string for analysis
		portnu, err := strconv.Atoi(port)
		// Add your own logic here to analyze the response and determine the service
		if len(serviceName) > 0 {

			fmt.Printf(color.Colorize(color.Green, "\n[+] Port %s is Open in IP %s with service %s.\n"), port, ip, serviceName)
			portInfo = PortInfo{
				Port:    port,
				Status:  "open",
				Service: serviceName + " " + tcpports.Detailedlist[portnu],
			}
		} else {

			if err != nil {
				fmt.Println(err)
			}
			fmt.Printf(color.Colorize(color.Green, "\n[+] Port %s is Open in IP %s with service %s.\n"), port, ip, tcpports.Commonlist[portnu])
			portInfo = PortInfo{
				Port:    port,
				Status:  "open",
				Service: tcpports.Commonlist[portnu],
			}

		}

		counterMu.Lock()
		defer counterMu.Unlock()
		counter++
		ipresult[ip] = append(ipresult[ip], portInfo)
	}

	return ipresult, ip, counter
}

func SynScan(ipadd, ip string, timeout int) (map[string][]PortInfo, string, int) {
	portstr := strings.Split(ipadd, ":")
	port := portstr[1]

	// Create the raw TCP packet with SYN flag set
	packet := []byte{
		0x00, 0x00, // Source port
		0x00, 0x01, // Destination port
		0x02,                   // Flags (SYN flag set)
		0x00, 0x00, 0x00, 0x00, // Sequence number
		0x00, 0x00, 0x00, 0x00, // Acknowledgment number
		0x00, 0x50, // Header length
		0x00, 0x00, // Window size
		0x00, 0x00, // Checksum
		0x00, 0x00, // Urgent pointer
	}

	// Send the SYN packet
	conn, err := net.DialTimeout("tcp", ipadd, time.Duration(timeout)*time.Millisecond)
	if err == nil {
		defer func(conn net.Conn) {
			err = conn.Close()
			if err != nil {
			}
		}(conn)

		// Send the packet
		_, err := conn.Write(packet)
		if err != nil {
			fmt.Printf("[-] Error sending SYN packet for port %s: %v\n", port, err)
			return ipresult, ip, counter
		}

		// Send a SYN-ACK packet to acknowledge the SYN packet
		synAckPacket := []byte{
			0x00, 0x00, // Source port (same as source port in SYN packet)
			0x00, 0x01, // Destination port (same as destination port in SYN packet)
			0x12,                   // Flags (SYN-ACK flag set)
			0x00, 0x00, 0x00, 0x00, // Sequence number (incremented by 1 from SYN packet)
			0x00, 0x00, 0x00, 0x00, // Acknowledgment number (same as acknowledgment number in SYN packet)
			0x00, 0x50, // Header length (same as header length in SYN packet)
			0x00, 0x00, // Window size (same as window size in SYN packet)
			0x00, 0x00, // Checksum (calculated based on the packet)
			0x00, 0x00, // Urgent pointer
		}

		_, err = conn.Write(synAckPacket)
		if err != nil {
			fmt.Printf("[-] Error sending SYN-ACK packet for port %s: %v\n", port, err)
			return ipresult, ip, counter
		}

		// Send a FIN packet to initiate the closing of the connection
		finPacket := []byte{
			0x00, 0x00, // Source port (same as source port in SYN packet)
			0x00, 0x01, // Destination port (same as destination port in SYN packet)
			0x14,                   // Flags (FIN flag set)
			0x00, 0x00, 0x00, 0x00, // Sequence number (same as sequence number in SYN-ACK packet)
			0x00, 0x00, 0x00, 0x01, // Acknowledgment number (incremented by 1 from SYN-ACK packet)
			0x00, 0x50, // Header length (same as header length in SYN packet)
			0x00, 0x00, // Window size (same as window size in SYN packet)
			0x00, 0x00, // Checksum (calculated based on the packet)
			0x00, 0x00, // Urgent pointer
		}

		_, err = conn.Write(finPacket)
		if err != nil {

			return ipresult, ip, counter
		}

		// Check for response
		resp := make([]byte, 1024)
		_, err = conn.Read(resp)
		portnum, _ := strconv.Atoi(port)
		if err != nil {
			// Other error, report it

			if err != nil {
				fmt.Println(err)
			}
			fmt.Printf(color.Colorize(color.Green, "\n[+] Port %s is Open in IP %s without response with service %s .\n"), port, ip, tcpports.Commonlist[portnum])
			m2 := PortInfo{port, "open", ""}
			defer counterMu.Unlock()
			counterMu.Lock()
			counter++
			ipresult[ip] = append(ipresult[ip], m2)
		} else {
			// Port might be closed or filtered
			fmt.Printf(color.Colorize(color.Green, "\n[+] Port %s is Open in IP %s with service %s .\n"), port, ip, tcpports.Commonlist[portnum])
			//fmt.Printf("[!] Port %s response received using SYN \n", port)
			m2 := PortInfo{port, "open", ""}
			defer counterMu.Unlock()
			counterMu.Lock()
			counter++
			ipresult[ip] = append(ipresult[ip], m2)
		}
	}
	return ipresult, ip, counter
}
func parseResponse(response []byte) string {
	// Check for specific keywords in the response to identify services
	if strings.Contains(string(response), "SSH") {
		return "SSH"
	} else if strings.Contains(string(response), "HTTP/1.1") {
		return "HTTP"
	} else if strings.Contains(string(response), "SMTP") {
		return "SMTP"
	} else {
		return ""
	}
}
