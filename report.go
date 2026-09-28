package main

import (
    "encoding/json"
    "fmt"
    "io"
    "os"
    "strings"
)

type Report struct {
    Target    string    `json:"target"`
    ScannedAt string    `json:"scanned_at"`
    Requests  int       `json:"requests_to_target"`
    Findings  []Finding `json:"findings"`
    CVEs      []CVE     `json:"cves"`
}

const (
    cReset  = "\x1b[0m"
    cBold   = "\x1b[1m"
    cDim    = "\x1b[2m"
    cRed    = "\x1b[31m"
    cGreen  = "\x1b[32m"
    cYellow = "\x1b[33m"
    cCyan   = "\x1b[36m"
)

var ansiOn bool

func paint(code, s string) string {
    if !ansiOn {
        return s
    }
    return code + s + cReset
}

func output(r Report, jsonMode, noColor bool, outFile string) error {
    if jsonMode {
        data, err := json.MarshalIndent(r, "", "  ")
        if err != nil {
            return err
        }
        fmt.Println(string(data))
        if outFile != "" {
            return os.WriteFile(outFile, append(data, '\n'), 0o644)
        }
        return nil
    }
    printConsole(os.Stdout, r, useColor(noColor))
    if outFile != "" {
        f, err := os.Create(outFile)
        if err != nil {
            return err
        }
        defer f.Close()
        printConsole(f, r, false) // plain text, no ANSI codes
    }
    return nil
}

func useColor(noColor bool) bool {
    if noColor {
        return false
    }
    fi, err := os.Stdout.Stat()
    if err != nil {
        return false
    }
    return fi.Mode()&os.ModeCharDevice != 0
}

func printConsole(w io.Writer, r Report, color bool) {
    ansiOn = color
    fmt.Fprintf(w, "%s\n", paint(cBold, "cvefinder report"))
    fmt.Fprintf(w, "target    : %s\n", r.Target)
    fmt.Fprintf(w, "scanned   : %s\n", r.ScannedAt)
    fmt.Fprintf(w, "requests  : %d\n\n", r.Requests)

    fmt.Fprintf(w, "%s\n", paint(cBold+cCyan, "[ fingerprints ]"))
    for _, f := range r.Findings {
        version := f.Version
        if version == "" {
            version = "?"
        }
        fmt.Fprintf(w, "  %-32s %-18s %-12s %s\n",
            f.Product, f.Category, version, truncate(strings.Join(f.Evidence, "; "), 90))
    }

    fmt.Fprintf(w, "\n%s\n", paint(cBold+cCyan, "[ CVE candidates (NVD) ]"))
    if len(r.CVEs) == 0 {
        fmt.Fprintln(w, "  none found for the identified products/versions")
    }
    for _, c := range r.CVEs {
        sev := c.Severity
        if sev == "" {
            sev = "UNRATED"
        }
        sevCol := cCyan
        switch sev {
        case "CRITICAL", "HIGH":
            sevCol = cRed
        case "MEDIUM":
            sevCol = cYellow
        case "LOW":
            sevCol = cGreen
        }
        score := "-"
        if c.CVSS > 0 {
            score = fmt.Sprintf("%.1f", c.CVSS)
        }
        confCol := cYellow
        if c.Confidence == "likely" {
            confCol = cBold + cGreen
        } else if c.Confidence == "unlikely" {
            confCol = cDim
        }

        fmt.Fprintf(w, "\n  %s %s  %s  %s  %s\n",
            paint(cRed, "*"),
            paint(cBold, c.ID),
            paint(sevCol, fmt.Sprintf("[%-8s %s]", sev, score)),
            paint(confCol, strings.ToUpper(c.Confidence)),
            paint(cDim, strings.Join(c.Sources, ", ")))

        if c.Version != "" {
            fmt.Fprintf(w, "    detected: %s %s\n", c.Product, c.Version)
        }
        var meta []string
        if c.Published != "" {
            meta = append(meta, "published "+dateOnly(c.Published))
        }
        if len(c.CWE) > 0 {
            meta = append(meta, strings.Join(c.CWE, " "))
        }
        if len(meta) > 0 {
            fmt.Fprintf(w, "    %s\n", paint(cDim, strings.Join(meta, " | ")))
        }
        if c.Summary != "" {
            fmt.Fprintf(w, "    %s\n", truncate(c.Summary, 300))
        }
        if c.MatchNote != "" {
            fmt.Fprintf(w, "    %s %s\n", paint(cBold, "match:"), c.MatchNote)
        }
        fmt.Fprintf(w, "    %s\n", paint(cDim, "https://nvd.nist.gov/vuln/detail/"+c.ID))
    }
    fmt.Fprintln(w)
}

func dateOnly(s string) string {
    if len(s) >= 10 {
        return s[:10]
    }
    return s
}