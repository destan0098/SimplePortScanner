package PortScanner

import (
	"PortScanner/internal/probes"
	tcpscanner "PortScanner/pkg/scanner/tcp"
	"bufio"
	"encoding/hex"
	"fmt"
	"github.com/TwiN/go-color"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

var counterMu sync.Mutex

var ipresult = make(map[string][]tcpscanner.PortInfo)
var counter int

func UdpScannerNew(ipadd, ip string, timeout int) (map[string][]tcpscanner.PortInfo, string, int) {
	recvData := make([]byte, 32)
	if timeout == 500 {
		timeout = 1000
	}
	portstr := strings.Split(ipadd, ":")
	port := portstr[1]
	timeoutdur := time.Duration(timeout) * time.Millisecond

	conn, err := net.Dial("udp", ipadd)
	if err != nil {
		log.Println("Error dialing UDP:", err)
		return ipresult, ip, counter
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Println("Error closing connection:", closeErr)
		}
	}()

	for _, probe := range probes.Probes {
		data, err := hex.DecodeString(probe.Data)

		if err != nil {
			log.Printf("Error in decoding probe data. Problem probe: '%s'", probe.Name)
			continue
		}

		_, err = conn.Write([]byte(data))
		if err != nil {
			log.Println("Error writing to UDP connection:", err)
			continue
		}

		err = conn.SetReadDeadline(time.Now().Add(timeoutdur))
		if err != nil {
			log.Println("Error setting UDP read deadline:", err)
			continue
		}

		recvLength, readErr := bufio.NewReader(conn).Read(recvData)
		if readErr != nil {
			if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
				//log.Println("Read operation timed out")
				continue
			}
			log.Println("Error reading from UDP connection:", readErr)
			continue
		}

		// Check the response for any service-specific information
		if recvLength != 0 {
			fmt.Printf(color.Colorize(color.Green, "\n[+] Port %s is Open in IP %s  .\n"), port, ip)
			m := tcpscanner.PortInfo{port, "open", ""}

			counterMu.Lock()
			ipresult[ip] = append(ipresult[ip], m)
			counter++
			counterMu.Unlock()
			break
		}
	}

	return ipresult, ip, counter
}
