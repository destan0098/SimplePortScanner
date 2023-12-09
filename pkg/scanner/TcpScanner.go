package PortScanner

import (
	"fmt"
	"github.com/TwiN/go-color"
	"net"
	"strings"
	"sync"
	"time"
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

		fmt.Printf(color.Colorize(color.Green, "[+] Port %s is Open in IP %s.\n"), port, ip)

		portInfo := PortInfo{
			Port:    port,
			Status:  "open",
			Service: "NoDetect",
		}

		counterMu.Lock()
		defer counterMu.Unlock()
		counter++
		ipresult[ip] = append(ipresult[ip], portInfo)
	}

	return ipresult, ip, counter
}
