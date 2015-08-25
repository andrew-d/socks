package main

import (
	"fmt"
	"log"
	"net"

	"github.com/armon/go-socks5"
	flag "github.com/ogier/pflag"
)

var (
	flagHost                  string
	flagPort                  uint16
	flagAllowedSourceIPs      StringSlice
	flagAllowedDestinationIPs StringSlice
)

func init() {
	flag.StringVarP(&flagHost, "host", "h", "", "host to listen on")
	flag.Uint16VarP(&flagPort, "port", "p", 8000, "port to listen on")
	flag.VarP(&flagAllowedSourceIPs, "source-ips", "s", "valid source IP addresses")
	flag.VarP(&flagAllowedDestinationIPs, "dest-ips", "d", "valid destination IP addresses")
}

type Rules struct{}

func (r Rules) AllowConnect(dstIP net.IP, dstPort int, srcIP net.IP, srcPort int) bool {
	log.Printf("AllowConnect: %s %d %s %d", dstIP, dstPort, srcIP, srcPort)

	var sourceAllowed, destAllowed bool

	if len(flagAllowedSourceIPs) > 0 {
		for _, ip := range flagAllowedSourceIPs {
			if ip == srcIP.String() {
				sourceAllowed = true
			}
		}
	} else {
		sourceAllowed = true
	}

	if len(flagAllowedDestinationIPs) > 0 {
		for _, ip := range flagAllowedDestinationIPs {
			if ip == dstIP.String() {
				destAllowed = true
			}
		}
	} else {
		destAllowed = true
	}

	return sourceAllowed && destAllowed
}

func (r Rules) AllowBind(dstIP net.IP, dstPort int, srcIP net.IP, srcPort int) bool {
	return false
}

func (r Rules) AllowAssociate(dstIP net.IP, dstPort int, srcIP net.IP, srcPort int) bool {
	return false
}

func main() {
	flag.Parse()

	if len(flagAllowedSourceIPs) > 0 {
		log.Println("Allowed source IPs:")
		for _, host := range flagAllowedSourceIPs {
			log.Printf("  - %s", host)
		}
	}

	if len(flagAllowedDestinationIPs) > 0 {
		log.Println("Allowed destination IPs:")
		for _, host := range flagAllowedDestinationIPs {
			log.Printf("  - %s", host)
		}
	}

	// Create a SOCKS5 server
	conf := &socks5.Config{
		Rules: Rules{},
	}
	server, err := socks5.New(conf)
	if err != nil {
		log.Fatalf("could not create SOCKS server: %s", err)
	}

	// Create SOCKS5 proxy on localhost port 8000
	addr := fmt.Sprintf("%s:%d", flagHost, flagPort)
	log.Printf("starting server on: %s", addr)
	if err := server.ListenAndServe("tcp", addr); err != nil {
		log.Fatalf("could not listen: %s", err)
	}
}
