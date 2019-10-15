package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type result struct {
	target  string
	ok      bool
	message string
}

const (
	tick  = "✔"
	cross = "✘"
)

var (
	iconGood   = "\033[32m" + tick + "\033[m"
	iconBad    = "\033[31m" + cross + "\033[m"
	httpClient *http.Client

	flagHelp     = flag.Bool("h", false, "display help")
	flagNoColour = flag.Bool("C", false, "inhibit colour output")
	flagIPv4     = flag.Bool("4", false, "force connection via IPv4")
	flagIPv6     = flag.Bool("6", false, "force connection via IPv6")
	flagTimeout  = flag.Duration("t", 2*time.Second, "timeout (DNS+connection)")
	flagResolv   = flag.Bool("r", false, "resolve names only")

	netmode = "tcp"
)

func Usage() {
	fmt.Fprintln(os.Stderr,
		`Usage:
	checkconn -h
	checkconn [flags] host1:port1 [host2:port2 https://host …]
	checkconn [flags] -r host1 [host2 …]

If the first argument is -r then checkconn will not determine connectivity but
will perform DNS resolution.

Flags:
  -r       Resolve names only.
  -4       Use IPv4 only.
  -6   	   Use IPv6 only.
  -C   	   Inhibit colour output.
  -t <val> Timeout (default: "2s").`)
}

func main() {
	flag.Parse()
	if *flagHelp {
		Usage()
		return
	}

	if *flagNoColour {
		iconGood = tick
		iconBad = cross
	}

	switch {
	case *flagIPv4 && *flagIPv6:
		fmt.Fprintln(os.Stderr, "can only specify one of -4 or -6")
		os.Exit(1)

	case *flagIPv4:
		netmode = "tcp4"

	case *flagIPv6:
		netmode = "tcp6"
	}

	if flag.NArg() == 0 {
		Usage()
		os.Exit(1)
	}

	httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: *flagTimeout,
	}

	if *flagResolv {
		CheckDNS(flag.Args())
	} else {
		CheckConn(flag.Args())
	}
}

func CheckConn(args []string) {
	var (
		results    []chan result
		nr, maxTgt int
	)

	for _, arg := range args {
		if len(arg) > maxTgt {
			maxTgt = len(arg)
		}
		r := make(chan result)
		results = append(results, r)
		go examine(r, arg)
		nr++
	}

	exitCode := 0
	for i := 0; i < nr; i++ {
		result := <-results[i]
		icon := iconGood
		if !result.ok {
			icon = iconBad
			exitCode = 1
		}
		fmt.Printf("%s %-*s: %s\n", icon, maxTgt, result.target,
			result.message)
	}
	os.Exit(exitCode)
}

func CheckDNS(args []string) {
	var (
		results    []chan []result
		nr, maxTgt int
	)

	resolv := &net.Resolver{
		PreferGo: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), *flagTimeout)
	for _, arg := range args {
		if len(arg) > maxTgt {
			maxTgt = len(arg)
		}
		r := make(chan []result)
		results = append(results, r)
		go lookup(ctx, resolv, r, arg)
		nr++
	}

	exitCode := 0
	for i := 0; i < nr; i++ {
		result := <-results[i]
		icon := iconGood
		if !result[0].ok {
			icon = iconBad
			exitCode = 1
		}

		tgt := result[0].target
		for _, r := range result {
			fmt.Printf("%s %-*s: %s\n", icon, maxTgt, tgt,
				r.message)
			tgt = ""
		}
	}
	cancel()

	os.Exit(exitCode)
}

func lookup(ctx context.Context, resolv *net.Resolver,
	results chan<- []result, target string) {
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	cut := strings.IndexAny(target, ":/")
	if cut != -1 {
		target = target[:cut]
	}

	var ret []result
	defer func() { results <- ret }()

	// lookup the CNAME first
	cname, err := resolv.LookupCNAME(ctx, target)
	if err != nil {
		ret = append(ret, result{
			target:  target,
			message: "ERR   | " + err.Error(),
		})
		return
	}

	// Go returns cname == target if there is no explicit CNAME record
	if cname != target && cname != target+"." {
		ret = append(ret, result{
			ok:      true,
			target:  target,
			message: "CNAME | " + cname,
		})
	}

	// now perform standard DNS lookup
	ips, err := resolv.LookupIPAddr(ctx, target)
	if err != nil {
		ret = append(ret, result{
			target:  target,
			message: "ERR   | " + err.Error(),
		})
		ret[0].ok = false
		return
	}

	if len(ips) == 0 {
		ret = append(ret, result{
			target:  target,
			message: "ERR   | no IP addresses found",
		})
		ret[0].ok = false
		return
	}

	for _, ip := range ips {
		if ip4 := ip.IP.To4(); ip4 != nil {
			ret = append(ret, result{
				target:  target,
				message: "A     | " + ip4.String(),
				ok:      true,
			})
		} else {
			ret = append(ret, result{
				target:  target,
				message: "AAAA  | " + ip.String(),
				ok:      true,
			})
		}
	}
}

func examine(results chan<- result, target string) {
	switch {
	case strings.HasPrefix(target, "http://"),
		strings.HasPrefix(target, "https://"):
		examineHTTP(results, target)
		return
	}

	start := time.Now()
	conn, err := net.DialTimeout(netmode, target, *flagTimeout)
	if err != nil {
		results <- result{
			target:  target,
			message: err.Error(),
		}
		return
	}

	// TODO: TLS?
	results <- result{
		target: target,
		ok:     true,
		message: fmt.Sprintf("connected after %.2fms",
			time.Since(start).Seconds()*1000),
	}
	conn.Close()
}

func examineHTTP(results chan<- result, target string) {
	// TODO would be nice to know if it's just an HTTP timeout, or TCP level
	start := time.Now()
	resp, err := httpClient.Get(target)
	if err != nil {
		results <- result{
			target:  target,
			message: err.Error(),
		}
		return
	}

	results <- result{
		target: target,
		ok:     true,
		message: fmt.Sprintf("HTTP %d after %.2fms",
			resp.StatusCode, time.Since(start).Seconds()*1000),
	}
}
