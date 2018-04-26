package main

import (
	"crypto/tls"
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
	iconGood = "\033[32m✔\033[m"
	iconBad  = "\033[31m✘\033[m"
)

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

func CheckDNS(args []string) {
	fmt.Fprintln(os.Stderr, "not implemented yet")
	os.Exit(1)
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
