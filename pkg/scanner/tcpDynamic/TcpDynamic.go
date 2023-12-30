package PortScanner

import (
	"fmt"
	"github.com/TwiN/go-color"
	tcpscanner "github.com/destan0098/SimplePortScanner/pkg/scanner/tcp"
	"net"
	"regexp"
	"strings"
	"time"
)

var ipresult = make(map[string][]tcpscanner.PortInfo)

var counter int

// Adjust the pool size as needed
func searchText(text, substring string) bool {
	return strings.Contains(text, substring)
}
func extractIPAddress(pattern, input string) (string, error) {
	// Define the regular expression pattern

	// Compile the regular expression
	re := regexp.MustCompile(pattern)

	// Find the match in the input string
	match := re.FindStringSubmatch(input)

	// Check if a match is found
	if len(match) < 2 {
		return "", fmt.Errorf("No IP address found in the input string")
	}

	// Return the extracted IP address
	return match[1], nil
}
func Tcpscannersingle(ipadd string, ip string, timeout int) (map[string][]tcpscanner.PortInfo, string, int) {
	var m2 tcpscanner.PortInfo

	//	m2.IP = ip
	portstr := strings.Split(ipadd, ":")
	port := portstr[1]
	conn, err := net.DialTimeout("tcp", ipadd, time.Duration(timeout)*time.Millisecond)
	if err == nil {
		counter++
		request := []byte("GET / HTTP/1.0\r\n\r\n")
		_, err = conn.Write(request)
		if err != nil {
			recover()
		}

		// Read the response
		//	buffer := make([]byte, 1024)
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			recover()
		}
		serverField := string(buffer[:n])

		//	fmt.Println(line)
		if searchText(string(buffer[:n]), "HTTP/1.1: ") {
			serverField = "HTTP/1.1"

		}
		if searchText(string(buffer[:n]), "Server: ") {
			serverField, _ = extractIPAddress(`Server:\s*(.+)`, string(buffer[:n]))

		}
		if searchText(string(buffer[:n]), "X-Powered-By: ") {
			serverField, _ = extractIPAddress(`X-Powered-By:\s*(.+)`, string(buffer[:n]))

		}
		if serverField == "" {
			serverField = "Not Detect"
		}
		serverFields := color.Colorize(color.Red, serverField)
		fmt.Printf(color.Colorize(color.Green, "[+] Port %s is Open in IP %s with "+color.Colorize(color.White, "service : %s")+" .\n"), port, ip, serverFields)
		m2.Port = port
		m2.Status = "open"
		m2.Service = serverField
		ipresult[ip] = append(ipresult[ip], m2)

	}

	return ipresult, ip, counter
}
