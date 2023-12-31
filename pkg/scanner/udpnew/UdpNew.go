package PortScanner

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/destan0098/SimplePortScanner/internal/probes"
	tcpscanner "github.com/destan0098/SimplePortScanner/pkg/scanner/tcp"
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
	//fmt.Println(ipadd)
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
		for _, payload := range probe.Payloads {
			data, err := hex.DecodeString(payload)

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
				return ipresult, ip, counter
			}
			break
		}
	}

	return ipresult, ip, counter
}
