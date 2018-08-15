package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
)

type result struct {
	target  string
	ok      bool
	message string
}

func icon(good bool) string {
	tty := isatty.IsTerminal(os.Stdout.Fd())
	if tty {
		if good {
			return "\033[32m✔\033[m"
		} else {
			return "\033[31m✘\033[m"
		}
	}

	if good {
		return "✔"
	}

	return "✘"
}

var (
	httpClient *http.Client
)

func Usage() {
	fmt.Fprintln(os.Stderr,
		`Usage:
	checkconn -h
	checkconn host1:port1 [host2:port2 https://host …]
	checkconn -r host1 [host2 …]

If the first argument is -r (or --resolv/--resolve) then checkconn will not
determine connectivity but will perform DNS resolution.`)
}

func main() {
	if len(os.Args) < 2 {
		Usage()
		os.Exit(1)
	}

	httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 2 * time.Second,
	}

	if len(os.Args[1]) > 0 && os.Args[1][0] == '-' {
		switch os.Args[1] {
		case "-h", "--help":
			Usage()
			return

		case "-r", "--resolv":
			CheckDNS(os.Args[2:])

		case "--":
			CheckConn(os.Args[2:])

		default:
			fmt.Fprintln(os.Stderr, "unrecognised argument: ",
				os.Args[1])
			os.Exit(1)
		}
	}

	CheckConn(os.Args[1:])
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
		good := true
		if !result.ok {
			good = false
			exitCode = 1
		}
		fmt.Printf("%s %-*s: %s\n", icon(good), maxTgt, result.target,
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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
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
		good := true
		if !result[0].ok {
			good = false
			exitCode = 1
		}

		tgt := result[0].target
		for _, r := range result {
			fmt.Printf("%s %-*s: %s\n", icon(good), maxTgt, tgt,
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
	conn, err := net.DialTimeout("tcp", target, time.Second)
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
