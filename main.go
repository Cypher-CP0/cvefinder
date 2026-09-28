package main

import (
    "context"
    "crypto/tls"
    "flag"
    "fmt"
    "net/http"
    "net/url"
    "os"
    "os/signal"
    "strings"
    "time"
)

var toolVersion = "1.0.0"

func main() {
    var (
        probe       = flag.Bool("probe", true, "send extra requests to well-known paths to improve fingerprinting")
        insecure    = flag.Bool("insecure", false, "skip TLS certificate verification (self-signed targets)")
        timeout     = flag.Duration("timeout", 15*time.Second, "per-request timeout for target requests")
        delay       = flag.Duration("delay", 150*time.Millisecond, "pause between requests to the target")
        nvdKey      = flag.String("nvd-key", "", "NVD API key (free: https://nvd.nist.gov/developers)")
        nvdInterval = flag.Duration("nvd-interval", 0, "min delay between NVD calls (0 = auto: 6s no key, 0.7s with key)")
        jsonOut     = flag.Bool("json", false, "emit machine-readable JSON on stdout (progress goes to stderr)")
        outFile     = flag.String("out", "", "also write the report to this file")
        noColor     = flag.Bool("no-color", false, "disable ANSI colors")
        userAgent   = flag.String("ua", "cvefinder/"+toolVersion, "User-Agent sent to the target")
        verbose     = flag.Bool("v", false, "verbose: log every request and match")
    )
    flag.Usage = usage
    flag.Parse()

    target := ""
    if flag.NArg() > 0 {
        target = flag.Arg(0)
    }
    target = strings.TrimSpace(target)
    if target == "" {
        usage()
        os.Exit(2)
    }
    if !strings.Contains(target, "://") {
        target = "http://" + target
    }
    u, err := url.Parse(target)
    if err != nil || u.Host == "" {
        fmt.Fprintf(os.Stderr, "error: invalid target URL %q\n", target)
        os.Exit(2)
    }

    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
    defer stop()

    client := &http.Client{
        Timeout: *timeout,
        Transport: &http.Transport{
            Proxy:               http.ProxyFromEnvironment,
            TLSClientConfig:     &tls.Config{InsecureSkipVerify: *insecure},
            MaxIdleConnsPerHost: 4,
        },
    }
    opts := scanOpts{probe: *probe, delay: *delay, ua: *userAgent, verbose: *verbose}

    // ---- phase 1: fingerprint the target ----
    fmt.Fprintf(os.Stderr, "[*] fingerprinting %s ...\n", target)
    findings, requests, err := fingerprint(ctx, client, u, opts)
    if err != nil {
        fmt.Fprintf(os.Stderr, "[!] %v\n", err)
        os.Exit(1)
    }
    if len(findings) == 0 {
        fmt.Fprintln(os.Stderr, "[!] no technologies identified — nothing to correlate CVEs against.")
        os.Exit(1)
    }

    // ---- phase 2: correlate against NVD ----
    interval := *nvdInterval
    if interval == 0 {
        if *nvdKey != "" {
            interval = 700 * time.Millisecond
        } else {
            interval = 6 * time.Second
        }
    }
    src := &nvdSource{
        apiKey:   *nvdKey,
        interval: interval,
        ua:       *userAgent,
        client:   &http.Client{
            Timeout:   60 * time.Second,
            Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
        },
    }

    fmt.Fprintf(os.Stderr, "[*] correlating %d finding(s) against the NVD database ...\n", len(findings))
    var cves []CVE
    for _, f := range findings {
        if ctx.Err() != nil {
            break
        }
        got, qerr := src.lookup(ctx, f)
        if qerr != nil {
            fmt.Fprintf(os.Stderr, "[!] %s: %v\n", f.Product, qerr)
            continue
        }
        cves = mergeCVEs(cves, got)
        if *verbose {
            fmt.Fprintf(os.Stderr, "    %s -> %d candidate CVE(s)\n", f.Product, len(got))
        }
    }
    sortCVEs(cves)

    rep := Report{
        Target:    target,
        ScannedAt: time.Now().UTC().Format(time.RFC3339),
        Requests:  requests,
        Findings:  findings,
        CVEs:      cves,
    }

    // ---- phase 3: report ----
    if err := output(rep, *jsonOut, *noColor, *outFile); err != nil {
        fmt.Fprintf(os.Stderr, "[!] %v\n", err)
        os.Exit(1)
    }

    var nL, nP, nU int
    for _, c := range cves {
        switch c.Confidence {
        case "likely":
            nL++
        case "possible":
            nP++
        default:
            nU++
        }
    }
    fmt.Fprintf(os.Stderr, "[*] done — %d finding(s), %d CVE(s): %d likely, %d possible, %d unlikely · %d request(s) to target\n",
        len(findings), len(cves), nL, nP, nU, requests)
}

func usage() {
    fmt.Fprintf(os.Stderr, `cvefinder %s — web application fingerprinting + CVE correlation

usage: cvefinder [flags] <target-url>

examples:
  cvefinder https://blog.example.com
  cvefinder -nvd-key XXXXXXXX-XXXX-XXXX -out report.json https://10.0.0.5:8443
  cvefinder -json -insecure https://staging.example.org | jq .

flags:
`, toolVersion)
    flag.PrintDefaults()
}