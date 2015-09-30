package main

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"

	"comail.io/go/colog"
	"github.com/armon/go-socks5"
	flag "github.com/ogier/pflag"
	"golang.org/x/crypto/ssh"
)

var (
	flagTrace                 bool
	flagVerbose               bool
	flagQuiet                 bool
	flagHost                  string
	flagPort                  uint16
	flagAllowedSourceIPs      StringSlice
	flagAllowedDestinationIPs StringSlice
	flagRemoteListener        string
)

func init() {
	flag.BoolVarP(&flagVerbose, "verbose", "v", false, "be more verbose")
	flag.BoolVarP(&flagQuiet, "quiet", "q", false, "be quiet")
	flag.BoolVarP(&flagTrace, "trace", "t", false, "trace bytes copied")

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
	log.Printf("debug: AllowConnect: %s:%d --> %s:%d", srcIP, srcPort, dstIP, dstPort)

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

func makeLogger() (*log.Logger, *colog.CoLog) {
	// Create logger
	logger := log.New(os.Stderr, "", 0)

	// Create colog instance
	cl := colog.NewCoLog(os.Stderr, "", 0)

	// This header is from the SOCKS package, and is actually at the 'Trace'
	// level, in that it shows all bytes copied
	colog.AddHeader("[DEBUG] ", colog.LTrace)

	// Overwrite both standard library and custom logger with this colog instance.
	log.SetOutput(cl)
	logger.SetOutput(cl)

	// Overwrite flags on stdlib logger
	log.SetPrefix("")
	log.SetFlags(0)

	return logger, cl
}

func main() {
	flag.Parse()
	logger, cl := makeLogger()

	if flagTrace {
		cl.SetMinLevel(colog.LTrace)
	} else if flagVerbose {
		cl.SetMinLevel(colog.LDebug)
	} else if flagQuiet {
		cl.SetMinLevel(colog.LWarning)
	} else {
		cl.SetMinLevel(colog.LInfo)
	}

	if len(flagAllowedSourceIPs) > 0 {
		log.Println("info: Allowed source IPs:")
		for _, host := range flagAllowedSourceIPs {
			log.Printf("  - %s", host)
		}
	}

	if len(flagAllowedDestinationIPs) > 0 {
		log.Println("info: Allowed destination IPs:")
		for _, host := range flagAllowedDestinationIPs {
			log.Printf("  - %s", host)
		}
	}

	addr := fmt.Sprintf("%s:%d", flagHost, flagPort)

	// Create a SOCKS5 server
	conf := &socks5.Config{
		Rules:  Rules{},
		Logger: logger,
	}
	server, err := socks5.New(conf)
	if err != nil {
		log.Fatalf("error: could not create SOCKS server: %s", err)
	}

	if flagRemoteListener == "" {
		// Create SOCKS5 proxy locally
		log.Printf("info: starting server on: %s", addr)
		if err := server.ListenAndServe("tcp", addr); err != nil {
			log.Fatalf("error: could not listen: %s", err)
		}

		return
	}

	u, err := url.Parse(flagRemoteListener)
	if err != nil {
		log.Fatalf("error: error parsing url: %s", err)
	}
	if u.Scheme != "ssh" {
		log.Fatalf("error: url is not an SSH url: %s", flagRemoteListener)
	}
	if u.User == nil {
		log.Fatalf("error: no username provided in remote listener", err)
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		log.Printf("warning: path, query, and fragment have no meaning in remote listener URL")
	}

	// TODO: ssh key?
	pass, havePass := u.User.Password()
	if !havePass {
		log.Fatalf("error: no password provided in remote listener", err)
	}

	config := &ssh.ClientConfig{
		User: u.User.Username(),
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
	}

	sshConn, err := ssh.Dial("tcp", u.Host, config)
	if err != nil {
		log.Fatalf("error: error dialing remote host: %s", err)
	}
	defer sshConn.Close()

	l, err := sshConn.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("error: error listening on remote host: %s", err)
	}
	defer l.Close()

	log.Printf("info: starting socks proxy on: %s (remote addr: %s)", u.Host, addr)
	if err := server.Serve(l); err != nil {
		log.Fatalf("error: could not serve socks proxy: %s", err)
	}

	log.Println("debug: done")
}
