# socks

This repository contains a very simple binary that creates a SOCKS proxy.
During my time as a security consultant, I often wanted to access a remote host
that was only accessible from a client's computer, but the various tools I use
were on my personal laptop.  This program contains a simple SOCKS proxy that
can operate in two modes:

### Mode One: Standard SOCKS

In this mode, you run the program as normal (e.g. `./socks -a 192.168.0.1 -p
8000`), and it opens and creates a SOCKS proxy for you.  Nothing particularly
fancy :-)

### Mode Two: SOCKS over SSH Client

Occasionally, you may not be able to open a listening port on the machine you
wish to run the proxy on (e.g. due to endpoint firewalls, no admin access,
etc.).  You can bypass this by (ab)using SSH port forwarding.  In this mode,
you run the proxy like so:

    ./socks ssh -a localhost -p 8000 -u andrew my-laptop:22

In this case, the program opens an SSH connection to the host `my-laptop` on
port 22, logs in with user `andrew` and prompts for a password, and then opens
a listening port on `my-laptop` with address `localhost:8000`.  As such, on
`my-laptop`, you can use the address `localhost:8000` as a SOCKS proxy, and it
will properly forward traffic back over the SSH connection and out of the SOCKS
proxy as normal.

## Building

    GO15VENDOREXPERIMENT=1 go build -v .

I have successfully used this program on all of Linux, OS X, and Windows.
