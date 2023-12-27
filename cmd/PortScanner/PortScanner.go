package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/briandowns/spinner"
	tcpscanner "github.com/destan0098/SimplePortScanner/pkg/scanner/tcp"
	tcpstatic "github.com/destan0098/SimplePortScanner/pkg/scanner/tcpstatic"
	PortScanner "github.com/destan0098/SimplePortScanner/pkg/scanner/udpnew"
	udpstatic "github.com/destan0098/SimplePortScanner/pkg/scanner/udpstaticnew"
	"github.com/urfave/cli/v2"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var outputs, counterPlus int
var worker, timeout int
var method, statics bool

var outputfilename, proto string

// var counterMu sync.Mutex
var start time.Time

func main() {
	runtime.GOMAXPROCS(1)
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "ip",
				Value:   "",
				Aliases: []string{"d"},
				Usage:   "Enter just one IP",
			},
			&cli.StringFlag{
				Name:    "CIDR",
				Value:   "",
				Aliases: []string{"c"},
				Usage:   "Enter just one CIDR",
			},

			&cli.StringFlag{
				Name:    "list",
				Value:   "",
				Aliases: []string{"l"},
				Usage:   "Enter a list from a text file",
			},
			&cli.StringFlag{
				Name:        "protocol",
				Value:       "",
				Aliases:     []string{"n"},
				Destination: &proto,
				Usage:       "Enter a protocol typ tcp or udp",
			},
			&cli.BoolFlag{
				Name:    "pipe",
				Aliases: []string{"p"},
				Usage:   "Enter just from a pipeline",
			},
			&cli.BoolFlag{
				Name:        "method",
				Aliases:     []string{"i"},
				Value:       false,
				Destination: &method,
				Usage:       "If enter this scan with Syn method",
			},
			&cli.BoolFlag{
				Name:        "static",
				Aliases:     []string{"s"},
				Value:       false,
				Destination: &statics,
				Usage:       "If enter this check static udp scan",
			},
			&cli.StringFlag{
				Name:    "PortRange",
				Value:   "",
				Aliases: []string{"r"},
				Usage:   "Enter Port",
			},
			&cli.IntFlag{
				Name:        "output",
				Aliases:     []string{"o"},
				Usage:       "Save in File 1 for text , 2 for csv , 3 for json and 4 for all",
				Destination: &outputs,
			},
			&cli.IntFlag{
				Name:        "timeout",
				Aliases:     []string{"t"},
				Value:       500,
				Usage:       "Time out Port Scanning in millisecond ",
				Destination: &timeout,
			},
			&cli.StringFlag{
				Name:        "filename",
				Aliases:     []string{"f"},
				Usage:       "output file name",
				Destination: &outputfilename,
			},
			&cli.IntFlag{
				Name:        "worker",
				Value:       300,
				Aliases:     []string{"w"},
				Usage:       "Default Value is 300",
				Destination: &worker,
			},
		},
		Action: func(cCtx *cli.Context) error {
			s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
			s.Prefix = "Waiting: "
			s.Start()
			start = time.Now()
			switch {
			case cCtx.String("ip") != "":
				withName(cCtx.String("ip"), cCtx.String("PortRange"))
			case cCtx.String("list") != "":
				withList(cCtx.String("list"), cCtx.String("PortRange"))
			case cCtx.Bool("pipe"):
				withPipe(cCtx.String("PortRange"))
			case cCtx.String("CIDR") != "":
				withCIDR(cCtx.String("CIDR"), cCtx.String("PortRange"))
			}

			elapsed := time.Since(start)
			s.Stop()
			fmt.Printf("page took %s", elapsed)
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

// readIPS read ip list from input file
func readIPS(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	var ipss []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ipss = append(ipss, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return ipss
}

// Join Port To ip and make address like 127.0.0.1:8080
func addPortToIP(ip, port string) string {
	address := net.JoinHostPort(ip, port)
	return address
}

// handle ports
func handlePorts(ip, portArray string) {
	switch {
	case strings.Contains(portArray, ","):
		handleMultiplePorts(ip, portArray)
	case strings.Contains(portArray, "-"):
		handlePortRange(ip, portArray)
	default:
		handleSinglePort(ip, portArray)
	}
}

// handle port with comma like 80,443
func handleMultiplePorts(ip, portArray string) {
	parts := strings.Split(portArray, ",")
	var wg sync.WaitGroup

	for _, part := range parts {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			handleSinglePort(ip, p)
		}(part)
	}

	wg.Wait()
}

// //////// handle port with range like 0-1024
func handlePortRange(ip, portArray string) {

	parts := strings.Split(portArray, "-")
	po1, _ := strconv.Atoi(parts[0])
	po2, _ := strconv.Atoi(parts[1])

	var wg sync.WaitGroup
	workerChan := make(chan struct{}, worker)
	if (proto == "udp" || proto == "UDP") && statics {
		handleSinglePort(ip, "1")

	} else {

		for i := po1; i <= po2; i++ {
			wg.Add(1)
			workerChan <- struct{}{}

			go func(j int) {
				defer func() {
					<-workerChan
					wg.Done()
				}()

				handleSinglePort(ip, strconv.Itoa(j))
			}(i)
		}

		wg.Wait()
	}
}

var res = make(map[string][]tcpscanner.PortInfo)
var ipName string
var counter int

// ///////////  handle single port
func handleSinglePort(ip, port string) {

	ipAdd := addPortToIP(ip, port)
	if proto == "tcp" || proto == "TCP" {

		if method == false {
			if statics {
				res, ipName, counter = tcpstatic.TcpScannerNewStatic(ipAdd, ip, timeout)
			} else {
				res, ipName, counter = tcpscanner.TcpScannerNew(ipAdd, ip, timeout)
			}

		} else {
			if statics {
				res, ipName, counter = tcpstatic.SynScanStatic(ipAdd, ip, timeout)
			} else {
				res, ipName, counter = tcpscanner.SynScan(ipAdd, ip, timeout)
			}
		}
	} else if proto == "udp" || proto == "UDP" {
		if statics {
			res, ipName, counter, _ = udpstatic.UdpStaticNew(ip, timeout)
			return
		} else {
			res, ipName, counter = PortScanner.UdpScannerNew(ipAdd, ip, timeout)
		}
	} else {
		fmt.Println(color.Colorize(color.Red, "[-] Please Select TCP or UDP Protocol "))
	}
	counterPlus = counter
	//	fmt.Println(res)

	writeResults(res, ipName)
}

// read ips from file
func withList(inputFile, portArray string) {
	if strings.Contains(portArray, ",") {
		parts := strings.Split(portArray, ",")
		var wg sync.WaitGroup

		IPs := readIPS(inputFile)
		for _, ip := range IPs {

			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				for _, part := range parts {
					handlePorts(ip, part)
				}
			}(ip)
			wg.Wait()

		}

	} else if strings.Contains(portArray, "-") {
		var wg sync.WaitGroup

		parts := strings.Split(portArray, "-")
		IPs := readIPS(inputFile)

		for _, ip := range IPs {

			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				handlePorts(ip, fmt.Sprintf("%s-%s", parts[0], parts[1]))
			}(ip)
			wg.Wait()

		}

	} else {
		IPs := readIPS(inputFile)
		var wg sync.WaitGroup

		for _, ip := range IPs {

			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				handlePorts(ip, portArray)
			}(ip)
			wg.Wait()

		}

	}

	fmt.Printf(color.Colorize(color.Green, "[+] Find %d Open Port.\n"), counterPlus)
}

// read ips from pipeline
func withPipe(portArray string) {

	scanner := bufio.NewScanner(os.Stdin)
	var wg sync.WaitGroup

	for scanner.Scan() {
		ip := scanner.Text()

		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			if strings.Contains(portArray, ",") {
				parts := strings.Split(portArray, ",")
				for _, part := range parts {
					handlePorts(ip, part)
				}
			} else if strings.Contains(portArray, "-") {
				parts := strings.Split(portArray, "-")
				handlePorts(ip, fmt.Sprintf("%s-%s", parts[0], parts[1]))
			} else {
				handlePorts(ip, portArray)
			}
		}(ip)
		wg.Wait()
		fmt.Printf(color.Colorize(color.Green, "[+] Find %d Open Port.\n"), counterPlus)

	}

}

// for input just one ip
func withName(ip, portarray string) {

	switch {
	case strings.Contains(portarray, ","):
		parts := strings.Split(portarray, ",")
		for _, part := range parts {
			handlePorts(ip, part)
		}
	case strings.Contains(portarray, "-"):
		parts := strings.Split(portarray, "-")
		handlePorts(ip, fmt.Sprintf("%s-%s", parts[0], parts[1]))
	default:
		handlePorts(ip, portarray)
	}
	fmt.Printf(color.Colorize(color.Green, "[+] Find %d Open Port .\n"), counterPlus)

}

// for input CIDR range line 127.0.0.0/24
func withCIDR(ip, portarray string) {

	if strings.Contains(portarray, ",") {
		parts := strings.Split(portarray, ",")
		for _, part := range parts {

			for processedIP := range processIPs(ip) {

				handlePorts(processedIP, part)
			}

		}

	} else if strings.Contains(portarray, "-") {
		parts := strings.Split(portarray, "-")
		for processedIP := range processIPs(ip) {
			handlePorts(processedIP, fmt.Sprintf("%s-%s", parts[0], parts[1]))
		}

	} else {
		for processedIP := range processIPs(ip) {
			handlePorts(processedIP, portarray)
		}

	}
	fmt.Printf(color.Colorize(color.Green, "[+] Find %d Open Port .\n"), counterPlus)

}

// increase  ip address
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// procees ips and convert cidr to ip
func processIPs(ip string) <-chan string {
	ipChan := make(chan string, 100)

	go func() {
		defer close(ipChan)
		if strings.Contains(ip, "/") {
			ipRange, ipNet, err := net.ParseCIDR(ip)
			if err != nil {
				fmt.Println("invalid CIDR")
				return
			}

			for ip := ipRange.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
				ipStr := ip.String()
				ipChan <- ipStr
			}
		}
	}()

	return ipChan
}

// write result to file output
func writeResults(results map[string][]tcpscanner.PortInfo, ipname string) {

	path := "output"
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(path, os.ModePerm)
		if err != nil {
			log.Println(err)
		}
	}

	if outputs == 1 {
		writeToFile(results, fmt.Sprintf("%s/%s.txt", outputfilename, ipname), func(ip, port string) string {
			return fmt.Sprintf("%s:%s\n", ip, port)
		})
	} else if outputs == 2 {
		writeToFile(results, fmt.Sprintf("%s/%s.txt", outputfilename, ipname), func(_, port string) string {
			return fmt.Sprintf("%s,%s,NoService\n", port, results[ipname][0].Status)
		})
	} else if outputs == 3 {
		writeToFile(results, fmt.Sprintf("output/%s.json", outputfilename), func(ip, port string) string {
			return fmt.Sprintf("%s:%s\n", ip, port)
		})
	} else if outputs == 4 {
		writeToFile(results, fmt.Sprintf("output/%s.txt", ipname), func(ip, port string) string {
			return fmt.Sprintf("%s:%s\n", ip, port)
		})
		writeToFile(results, fmt.Sprintf("output/%s.csv", ipname), func(_, port string) string {
			return fmt.Sprintf("NoIP,%s,%s,NoService\n", port, results[ipname][0].Status)
		})
		writeToFile(results, fmt.Sprintf("output/%s.json", outputfilename), func(_, _ string) string {
			jsonData, err := json.MarshalIndent(results, "", " ")
			if err != nil {
				log.Fatal(err)
			}
			return string(jsonData)
		})
	}
}

// write text output file
func writeTextFile(file *os.File, results map[string][]tcpscanner.PortInfo, format func(ip, port string) string) {
	for ip, ports := range results {
		for _, port := range ports {
			line := format(ip, port.Port)
			if _, err := file.WriteString(line); err != nil {
				log.Println(err)
			}
		}
	}
}

// write csv output file
func writeCSVFile(file *os.File, results map[string][]tcpscanner.PortInfo) {
	writer := csv.NewWriter(file)
	defer writer.Flush()

	err := writer.Write([]string{"PORT", "Status", "Service"})
	if err != nil {
		log.Fatal(err)
	}

	for _, ports := range results {
		for _, port := range ports {
			record := []string{port.Port, port.Status, port.Service}
			if err := writer.Write(record); err != nil {
				log.Println(err)
			}
		}
	}
}

// write json output file
func writeJSONFile(file *os.File, results map[string][]tcpscanner.PortInfo) {
	jsonData, err := json.MarshalIndent(results, "", " ")
	if err != nil {
		log.Fatal(err)
	}

	if _, err := file.Write(jsonData); err != nil {
		log.Fatal(err)
	}
}

// detect file format to save output file
func writeToFile(results map[string][]tcpscanner.PortInfo, filePath string, format func(ip, port string) string) {
	file, err := os.Create(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Println(err)
		}
	}(file)

	switch {
	case strings.HasSuffix(filePath, ".txt"):
		writeTextFile(file, results, format)
	case strings.HasSuffix(filePath, ".csv"):
		writeCSVFile(file, results)
	case strings.HasSuffix(filePath, ".json"):
		writeJSONFile(file, results)
	default:
		log.Fatal("Unsupported file format")
	}
}
