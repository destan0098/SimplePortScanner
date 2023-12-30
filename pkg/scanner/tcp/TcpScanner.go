package PortScanner

import (
	"fmt"
	"github.com/TwiN/go-color"
	"net"
	"strings"
	"time"
)

type PortInfo struct {
	Port    string
	Status  string
	Service string
}

var ipresult = make(map[string][]PortInfo)
var counter int

func Tcpscannersingle(address string, ip string, timeout int) (map[string][]PortInfo, string, int) {
	var m2 PortInfo

	//	m2.IP = ip
	portstr := strings.Split(address, ":")
	port := portstr[1]
	_, err := net.DialTimeout("tcp", address, time.Duration(timeout)*time.Millisecond)
	if err == nil {
		counter++

		fmt.Printf(color.Colorize(color.Green, "\n[+] Port %s is Open in IP %s .\n"), port, ip)
		m2.Port = port
		m2.Status = "open"
		m2.Service = "NoDetect"
		ipresult[ip] = append(ipresult[ip], m2)

	}

	return ipresult, ip, counter
}
