package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/urfave/cli/v2"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	tcpscanner "github.com/destan0098/SimplePortScanner/pkg/scanner" // Replace with the actual import path
)

//
//type PageVariables struct {
//	Title string
//}

var outputs, counterPlus int
var worker, timeout int
var outputfilename string

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
			&cli.BoolFlag{
				Name:    "pipe",
				Aliases: []string{"p"},
				Usage:   "Enter just from a pipeline",
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
			fmt.Printf("page took %s", elapsed)
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

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

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domains = append(domains, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return domains
}
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

// ////////
func handlePortRange(ip, portArray string) {
	parts := strings.Split(portArray, "-")
	po1, _ := strconv.Atoi(parts[0])
	po2, _ := strconv.Atoi(parts[1])

	var wg sync.WaitGroup
	workerChan := make(chan struct{}, worker)

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

// ///////////
func handleSinglePort(ip, port string) {
	ipAdd := addPortToIP(ip, port)
	res, ipName, counter := tcpscanner.TcpScannerNew(ipAdd, ip, timeout)
	counterPlus = counter
	//	fmt.Println(res)

	writeResults(res, ipName)
}

// /end handle ports
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
		}

		wg.Wait()
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
		}

		wg.Wait()
	} else {
		IPs := readIPS(inputFile)
		var wg sync.WaitGroup

		for _, ip := range IPs {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				handlePorts(ip, portArray)
			}(ip)
		}

		wg.Wait()
	}

	fmt.Printf(color.Colorize(color.Green, "[+] Find %d Open Port.\n"), counterPlus)
}

//	func withPipe(portarray string, worker int) {
//		scanner := bufio.NewScanner(os.Stdin)
//		for scanner.Scan() {
//			ip := scanner.Text()
//			handlePorts(ip, portarray, worker)
//		}
//		fmt.Printf(color.Colorize(color.Green, "[+] Find %d Open Port .\n"), counterplus)
//	}
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
	}

	wg.Wait()
	fmt.Printf(color.Colorize(color.Green, "[+] Find %d Open Port.\n"), counterPlus)
}

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

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

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

func writeResults(results map[string][]tcpscanner.PortInfo, ipname string) {

	path := "output"
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(path, os.ModePerm)
		if err != nil {
			log.Println(err)
		}
	}

	if outputs == 1 {
		writeToFile(results, fmt.Sprintf("output/%s.txt", ipname), func(ip, port string) string {
			return fmt.Sprintf("%s:%s\n", ip, port)
		})
	} else if outputs == 2 {
		writeToFile(results, fmt.Sprintf("output/%s.csv", ipname), func(_, port string) string {
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

func writeJSONFile(file *os.File, results map[string][]tcpscanner.PortInfo) {
	jsonData, err := json.MarshalIndent(results, "", " ")
	if err != nil {
		log.Fatal(err)
	}

	if _, err := file.Write(jsonData); err != nil {
		log.Fatal(err)
	}
}
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

/*
func writeResults(results map[string][]tcpscanner.PortInfo, ipname string) {
	path := "output"
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(path, os.ModePerm)
		if err != nil {
			log.Println(err)
		}
	}
	if outputs == 1 {
		writeToCSV(results, ipname)
	} else if outputs == 2 {
		writeToJSON(results, outputfilename)
	} else if outputs == 3 {
		writeToText(results, ipname)
	} else if outputs == 4 {
		writeToCSV(results, ipname)
		writeToText(results, ipname)
		writeToJSON(results, outputfilename)
	}

}
func writeToText(results map[string][]tcpscanner.PortInfo, ipname string) {
	file, err := os.Create("output/" + ipname + ".txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	for ip, ports := range results {
		for _, port := range ports {
			line := fmt.Sprintf("%s:%s\n", ip, port.Port)
			if _, err := file.WriteString(line); err != nil {
				log.Println(err)
			}
		}
	}
}
func writeToCSV(results map[string][]tcpscanner.PortInfo, ipname string) {

	file, err := os.Create("output/" + ipname + ".csv")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()
	err = writer.Write([]string{"IP", "PORT", "Status", "Service"})
	if err != nil {
		log.Fatal(err)
	}
	for _, ports := range results {

		record := []string{ipname, ports[0].Port, ports[0].Status, ports[0].Service}

		if err := writer.Write(record); err != nil {

		}
	}

}

func writeToJSON(results map[string][]tcpscanner.PortInfo, ipname string) {

	files, err := json.MarshalIndent(results, "", " ")
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile("output/"+ipname+".json", files, 0644)
	if err != nil {
		log.Fatal(err)
	}

}
*/
