package PortScanner

import (
	"fmt"
	"github.com/TwiN/go-color"
	tcpport "github.com/destan0098/SimplePortScanner/internal/TcpPorts"
	tcpscanner "github.com/destan0098/SimplePortScanner/pkg/scanner/tcp"
	"net"
	"strconv"
	"sync"
	"time"
)

var ipresult = make(map[string][]tcpscanner.PortInfo)
var counter int
var counterMu sync.Mutex

// TcpScannerNew Adjust the pool size as needed
func TcpScannerNewStatic(ip string, timeout int) (map[string][]tcpscanner.PortInfo, string, int) {

	for port, services := range tcpport.Commonlist {

		portstr := strconv.Itoa(port)
		ipadd := net.JoinHostPort(ip, portstr)

		_, err := net.DialTimeout("tcp", ipadd, time.Duration(timeout)*time.Millisecond)
		if err == nil {
			fmt.Printf(color.Colorize(color.Green, "[+] Port %d is Open in IP %s with "+color.Colorize(color.White, "service : %s")+" .\n"), port, ip, services)

			m2 := tcpscanner.PortInfo{Port: portstr, Status: "Open", Service: services}
			ipresult[ip] = append(ipresult[ip], m2)
			continue

		}

	}
	return ipresult, "", counter
}
