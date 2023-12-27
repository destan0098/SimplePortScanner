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
	"strconv"
	"sync"
	"time"
)

var ipresult = make(map[string][]tcpscanner.PortInfo)
var counter int
var mu sync.Mutex // Mutex to synchronize access to the counter and map
func UdpProbe(ip, probename, probestring string, probeport, timeout int, wg *sync.WaitGroup) {
	defer wg.Done()
	var m tcpscanner.PortInfo
	recvData := make([]byte, 32)
	port := strconv.Itoa(probeport)
	address := net.JoinHostPort(ip, port)
	//fmt.Println(address)
	conn, errDial := net.Dial("udp", address)

	if errDial != nil {
		return
	}

	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(conn)

	errConndead := conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))
	if errConndead != nil {
		log.Println("Error setting UDP read deadline:", errConndead)
		return
	}

	data, errDecode := hex.DecodeString(probestring)
	if errDecode != nil {
		log.Printf("Error in decoding probe data. Problem probe: '%s'", probename)
		return
	}

	_, errWrite := conn.Write(data)
	if errWrite != nil {
		log.Println("Error writing to UDP connection:", errWrite)
		return
	}

	recvLength, readErr := bufio.NewReader(conn).Read(recvData)
	if readErr != nil {
		if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
			//log.Println("Read operation timed out")

			return
		}
		//	log.Println("Error reading from UDP connection:", readErr)
		return
	}

	// Check the response for any service-specific information
	if recvLength != 0 {
		fmt.Printf(color.Colorize(color.Green, "\n[+] Port %s is Open in IP %s with %s  .\n"), port, ip, probename)
		m = tcpscanner.PortInfo{Port: port, Service: probename, Status: "Open"}

		mu.Lock()
		counter++
		ipresult[ip] = append(ipresult[ip], m)
		mu.Unlock()
	}

}

func UdpStaticNew(ip string, timeout int) (map[string][]tcpscanner.PortInfo, string, int, bool) {
	fmt.Printf(color.Colorize(color.Green, "\n[+] scanning IP %s  .\n"), ip)
	var wg sync.WaitGroup

	for _, probe := range probes.Probes {
		//fmt.Println(ip)
		wg.Add(1)
		go UdpProbe(ip, probe.Name, probe.Data, probe.Port, timeout, &wg)

	}
	wg.Wait()
	return ipresult, ip, counter, false
}
