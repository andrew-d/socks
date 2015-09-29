package main

import (
	"fmt"
	"log"
	"net"
	"net/url"

	"github.com/armon/go-socks5"
	flag "github.com/ogier/pflag"
	"golang.org/x/crypto/ssh"
)

var (
	flagHost                  string
	flagPort                  uint16
	flagAllowedSourceIPs      StringSlice
	flagAllowedDestinationIPs StringSlice
	flagRemoteListener        string
)

func init() {
	flag.StringVarP(&flagHost, "host", "h", "", "host to listen on")
	flag.Uint16VarP(&flagPort, "port", "p", 8000, "port to listen on")
	flag.VarP(&flagAllowedSourceIPs, "source-ips", "s",
		"valid source IP addresses (if none given, all allowed)")
	flag.VarP(&flagAllowedDestinationIPs, "dest-ips", "d",
		"valid destination IP addresses (if none given, all allowed)")
	flag.StringVar(&flagRemoteListener, "remote-listener", "",
		"open the SOCKS port on the remote address (e.g. ssh://user:pass@host:port)")
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

	addr := fmt.Sprintf("%s:%d", flagHost, flagPort)

	// Create a SOCKS5 server
	conf := &socks5.Config{
		Rules: Rules{},
	}
	server, err := socks5.New(conf)
	if err != nil {
		log.Fatalf("could not create SOCKS server: %s", err)
	}

	if flagRemoteListener == "" {
		// Create SOCKS5 proxy locally
		log.Printf("starting server on: %s", addr)
		if err := server.ListenAndServe("tcp", addr); err != nil {
			log.Fatalf("could not listen: %s", err)
		}

		return
	}

	u, err := url.Parse(flagRemoteListener)
	if err != nil {
		log.Fatalf("error parsing url: %s", err)
	}
	if u.Scheme != "ssh" {
		log.Fatalf("url is not an SSH url: %s", flagRemoteListener)
	}
	if u.User == nil {
		log.Fatalf("no username provided in remote listener", err)
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		log.Printf("warning: path, query, and fragment have no meaning in remote listener URL")
	}

	// TODO: ssh key?
	pass, havePass := u.User.Password()
	if !havePass {
		log.Fatalf("no password provided in remote listener", err)
	}

	config := &ssh.ClientConfig{
		User: u.User.Username(),
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
	}

	sshConn, err := ssh.Dial("tcp", u.Host, config)
	if err != nil {
		log.Fatalf("error dialing remote host: %s", err)
	}
	defer sshConn.Close()

	l, err := sshConn.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("error listening on remote host: %s", err)
	}
	defer l.Close()

	log.Printf("starting socks proxy on: %s (remote addr: %s)", u.Host, addr)
	if err := server.Serve(l); err != nil {
		log.Fatalf("could not serve socks proxy: %s", err)
	}

	fmt.Println("done")
}
