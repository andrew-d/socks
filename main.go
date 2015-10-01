package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"comail.io/go/colog"
	"github.com/armon/go-socks5"
	"github.com/bgentry/speakeasy"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	// Global flags
	flagTrace                 bool
	flagVerbose               bool
	flagQuiet                 bool
	flagHost                  string
	flagPort                  uint16
	flagAllowedSourceIPs      StringSlice
	flagAllowedDestinationIPs StringSlice

	// SSH flags
	flagSSHUsername     string
	flagSSHPassword     string
	flagSSHIdentityFile string

	// Derived flags
	flagAddr string

	// Logger instance
	logger *log.Logger
)

var socksCommand = &cobra.Command{
	Use:              "socks",
	Short:            "simple utility to start a SOCKS proxy",
	Run:              runSocks,
	PersistentPreRun: preRun,
}

var sshCommand = &cobra.Command{
	Use:   "ssh <remote host>",
	Short: "connect to a remote host over SSH and start a SOCKS proxy there",
	Run:   runSSH,
}

func init() {
	// Global flags
	pf := socksCommand.PersistentFlags()
	pf.BoolVarP(&flagVerbose, "verbose", "v", false, "be more verbose")
	pf.BoolVarP(&flagQuiet, "quiet", "q", false, "be quiet")
	pf.BoolVarP(&flagTrace, "trace", "t", false, "trace bytes copied")

	pf.StringVarP(&flagHost, "address", "a", "", "address to listen on")
	pf.Uint16VarP(&flagPort, "port", "p", 8000, "port to listen on")
	pf.VarP(&flagAllowedSourceIPs, "source-ips", "s",
		"valid source IP addresses (if none given, all allowed)")
	pf.VarP(&flagAllowedDestinationIPs, "dest-ips", "d",
		"valid destination IP addresses (if none given, all allowed)")

	// SSH flags
	sshFlags := sshCommand.Flags()
	sshFlags.StringVarP(&flagSSHUsername, "username", "u", os.Getenv("USER"),
		"connect as the given user")
	sshFlags.StringVar(&flagSSHPassword, "password", "",
		"use the given password to connect")
	sshFlags.StringVarP(&flagSSHIdentityFile, "identity-file", "i", "",
		"use the given SSH key to connect to the remote host")
}

func preRun(cmd *cobra.Command, args []string) {
	var cl *colog.CoLog
	logger, cl = makeLogger()

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

	// Get address flag
	flagAddr = fmt.Sprintf("%s:%d", flagHost, flagPort)
}

func main() {
	socksCommand.AddCommand(sshCommand)
	socksCommand.Execute()
}

func runSocks(cmd *cobra.Command, args []string) {
	if len(args) != 0 {
		log.Println("warn: the default command does not take any arguments")
	}

	// Listen on a local port and serve.
	l, err := net.Listen("tcp", flagAddr)
	if err != nil {
		log.Fatalf("error: error listening: %s", err)
	}

	startSocksServer(l, flagAddr)
}

func runSSH(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		log.Printf("error: invalid number of arguments provided (%d)", len(args))
		return
	}

	config := &ssh.ClientConfig{
		User: flagSSHUsername,
		Auth: []ssh.AuthMethod{},
	}

	// Password auth or prompt callback
	if flagSSHPassword != "" {
		config.Auth = append(config.Auth, ssh.Password(flagSSHPassword))
	} else {
		config.Auth = append(config.Auth, ssh.PasswordCallback(func() (string, error) {
			prompt := fmt.Sprintf("%s@%s's password: ", flagSSHUsername, args[0])
			return speakeasy.Ask(prompt)
		}))
	}

	// Key auth
	if flagSSHIdentityFile != "" {
		keyData, err := ioutil.ReadFile(flagSSHIdentityFile)
		if err != nil {
			log.Fatalf("error: could not read key file `%s`: %s", flagSSHIdentityFile, err)
		}

		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			log.Fatalf("error: could not parse key file `%s`: %s", flagSSHIdentityFile, err)
		}

		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	// SSH agent auth
	if agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err != nil {
		config.Auth = append(config.Auth,
			ssh.PublicKeysCallback(agent.NewClient(agentConn).Signers))
	}

	// TODO: keyboard-interactive auth, e.g. for two-factor

	log.Printf("debug: auth methods are: %#v", config.Auth)

	// Dial the SSH connection
	sshConn, err := ssh.Dial("tcp", args[0], config)
	if err != nil {
		log.Fatalf("error: error dialing remote host: %s", err)
	}
	defer sshConn.Close()

	// Listen on remote
	l, err := sshConn.Listen("tcp", flagAddr)
	if err != nil {
		log.Fatalf("error: error listening on remote host: %s", err)
	}

	// Start SOCKS server.
	startSocksServer(l, args[0])
}

func startSocksServer(l net.Listener, listenHost string) error {
	defer l.Close()

	// Create a SOCKS5 server
	conf := &socks5.Config{
		Rules:  Rules{},
		Logger: logger,
	}
	server, err := socks5.New(conf)
	if err != nil {
		log.Printf("error: could not create SOCKS server: %s", err)
		return err
	}

	log.Printf("info: starting socks proxy on: %s (proxy addr: %s)", listenHost, flagAddr)
	if err := server.Serve(l); err != nil {
		log.Printf("error: could not serve socks proxy: %s", err)
		return err
	}

	log.Println("debug: done")
	return nil
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
