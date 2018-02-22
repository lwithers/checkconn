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

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: checkconn host1:port1 "+
			"[host2:port2 https://host …]")
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

	var (
		results    []chan result
		nr, maxTgt int
	)

	for _, arg := range os.Args[1:] {
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
