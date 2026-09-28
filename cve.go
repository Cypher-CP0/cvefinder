package main

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "slices"
    "sort"
    "strconv"
    "strings"
    "time"
)

const nvdEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// ---------------------------------------------------------------------------
// normalized CVE record (what the report is made of)
// ---------------------------------------------------------------------------

type CVE struct {
    ID         string   `json:"id"`
    Sources    []string `json:"sources"`               // which finding(s) raised it
    Product    string   `json:"product,omitempty"`
    Version    string   `json:"version,omitempty"`
    Confidence string   `json:"confidence"`            // likely | possible | unlikely
    MatchNote  string   `json:"match_note,omitempty"`
    Severity   string   `json:"severity,omitempty"`
    CVSS       float64  `json:"cvss,omitempty"`
    CWE        []string `json:"cwe,omitempty"`
    Published  string   `json:"published,omitempty"`
    Summary    string   `json:"summary"`
    References []string `json:"references,omitempty"`
}

// ---------------------------------------------------------------------------
// NVD JSON shapes (only the fields we consume)
// ---------------------------------------------------------------------------

type nvdSource struct {
    apiKey   string
    interval time.Duration
    ua       string
    client   *http.Client
    last     time.Time
}

type nvdReply struct {
    TotalResults    int  `json:"totalResults"`
    ResultsPerPage  int  `json:"resultsPerPage"`
    StartIndex      int  `json:"startIndex"`
    Vulnerabilities []struct {
        Cve nvdCve `json:"cve"`
    } `json:"vulnerabilities"`
}

type nvdCve struct {
    Id           string `json:"id"`
    Published    string `json:"published"`
    LastModified string `json:"lastModified"`
    Descriptions []struct {
        Lang  string `json:"lang"`
        Value string `json:"value"`
    } `json:"descriptions"`
    Metrics struct {
        CvssMetricV40 []nvdMetric `json:"cvssMetricV40"`
        CvssMetricV31 []nvdMetric `json:"cvssMetricV31"`
        CvssMetricV30 []nvdMetric `json:"cvssMetricV30"`
        CvssMetricV2  []nvdMetric `json:"cvssMetricV2"`
    } `json:"metrics"`
    Weaknesses []struct {
        Description []struct {
            Value string `json:"value"`
        } `json:"description"`
    } `json:"weaknesses"`
    References []struct {
        Url  string   `json:"url"`
        Tags []string `json:"tags"`
    } `json:"references"`
    Configurations []struct {
        Nodes []struct {
            Operator string        `json:"operator"`
            CpeMatch []nvdCpeMatch `json:"cpeMatch"`
        } `json:"nodes"`
    } `json:"configurations"`
}

type nvdMetric struct {
    CvssData struct {
        BaseScore    float64 `json:"baseScore"`
        BaseSeverity string  `json:"baseSeverity"`
    } `json:"cvssData"`
    BaseSeverity string `json:"baseSeverity"` // CVSS v2 puts severity outside cvssData
}

type nvdCpeMatch struct {
    Vulnerable            bool   `json:"vulnerable"`
    Criteria              string `json:"criteria"`   // CPE 2.3 name (NVD 2.0)
    CpeName23             string `json:"cpeName23"` // older/alternate spelling, just in case
    VersionStartIncluding string `json:"versionStartIncluding"`
    VersionStartExcluding string `json:"versionStartExcluding"`
    VersionEndIncluding   string `json:"versionEndIncluding"`
    VersionEndExcluding   string `json:"versionEndExcluding"`
}

func (m nvdCpeMatch) cpe() string {
    if m.Criteria != "" {
        return m.Criteria
    }
    return m.CpeName23
}

// ---------------------------------------------------------------------------
// querying
// ---------------------------------------------------------------------------

func (s *nvdSource) lookup(ctx context.Context, f Finding) ([]CVE, error) {
    var all []nvdCve

    switch {
    case f.Version != "" && len(f.CPEs) > 0:
        // precise: query every CPE alias with the detected version,
        // NVD's cpeName filter does server-side range matching
        for _, base := range f.CPEs {
            got, err := s.fetchQuery(ctx, url.Values{
                "cpeName":        {base + ":" + f.Version + ":*:*:*:*:*:*:*"},
                "resultsPerPage": {"2000"},
            })
            if err != nil {
                return nil, err
            }
            all = append(all, got...)
        }
    case len(f.Keywords) > 0:
        // no version (or no CPE): description keyword search, results are "possible"
        got, err := s.fetchQuery(ctx, url.Values{
            "keywordSearch":  {f.Keywords[0]},
            "resultsPerPage": {"2000"},
        })
        if err != nil {
            return nil, err
        }
        all = append(all, got...)
    }

    var out []CVE
    seen := map[string]bool{}
    for _, c := range all {
        if seen[c.Id] {
            continue
        }
        seen[c.Id] = true
        out = append(out, evaluateCVE(c, f))
    }
    return out, nil
}

func (s *nvdSource) fetchQuery(ctx context.Context, params url.Values) ([]nvdCve, error) {
    var out []nvdCve
    start := 0
    for {
        params.Set("startIndex", strconv.Itoa(start))
        body, err := s.get(ctx, nvdEndpoint+"?"+params.Encode())
        if err != nil {
            return out, err
        }
        var rep nvdReply
        if err := json.Unmarshal(body, &rep); err != nil {
            return out, fmt.Errorf("NVD response parse error: %w", err)
        }
        for _, v := range rep.Vulnerabilities {
            out = append(out, v.Cve)
        }
        if rep.ResultsPerPage == 0 {
            return out, nil
        }
        start += rep.ResultsPerPage
        if start >= rep.TotalResults {
            return out, nil
        }
    }
}

func (s *nvdSource) get(ctx context.Context, rawURL string) ([]byte, error) {
    const maxAttempts = 4
    for attempt := 1; attempt <= maxAttempts; attempt++ {
        // client-side rate limiting (NVD: 5 req / 30 s without a key, 50 / 30 s with)
        wait := s.interval - time.Since(s.last)
        if wait > 0 {
            select {
            case <-time.After(wait):
            case <-ctx.Done():
                return nil, ctx.Err()
            }
        }
        s.last = time.Now()

        req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
        if err != nil {
            return nil, err
        }
        req.Header.Set("User-Agent", s.ua)
        if s.apiKey != "" {
            req.Header.Set("apiKey", s.apiKey)
        }
        resp, err := s.client.Do(req)
        if err != nil {
            return nil, err
        }
        body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
        resp.Body.Close()

        switch {
        case resp.StatusCode == http.StatusOK:
            return body, nil
        case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
            if attempt == maxAttempts {
                return nil, fmt.Errorf("NVD rate limit hit (HTTP %d) — get a free key at https://nvd.nist.gov/developers and pass -nvd-key", resp.StatusCode)
            }
            select {
            case <-time.After(time.Duration(attempt*10) * time.Second):
            case <-ctx.Done():
                return nil, ctx.Err()
            }
        default:
            return nil, fmt.Errorf("NVD returned HTTP %d", resp.StatusCode)
        }
    }
    return nil, fmt.Errorf("unreachable")
}

// ---------------------------------------------------------------------------
// evaluation: does this CVE actually apply to our finding?
// ---------------------------------------------------------------------------

func evaluateCVE(c nvdCve, f Finding) CVE {
    cv := CVE{
        ID:         c.Id,
        Published:  c.Published,
        Sources:    []string{f.Product},
        Product:    f.Product,
        Version:    f.Version,
        Summary:    description(c),
        References: refList(c),
    }
    cv.Severity, cv.CVSS = severityOf(c)
    cv.CWE = cweOf(c)
    cv.Confidence, cv.MatchNote = bestMatch(c, f)
    return cv
}

// bestMatch walks the CVE's CPE criteria, finds ours, and evaluates the
// version ranges. NOTE: this approximates the NVD configurations as a flat
// OR of all criteria — good enough for triage, not a formal CPE evaluator.
func bestMatch(c nvdCve, f Finding) (string, string) {
    if f.Version == "" {
        return "possible", "product matched, version not detected — verify manually"
    }
    rank := map[string]int{"": 0, "unlikely": 1, "possible": 2, "likely": 3}
    best, note := "", ""
    for _, cfg := range c.Configurations {
        for _, node := range cfg.Nodes {
            for _, m := range node.CpeMatch {
                if !m.Vulnerable {
                    continue
                }
                vendor, product, critVer, ok := parseCPE(m.cpe())
                if !ok || !cpeBelongs(f.CPEs, vendor, product) {
                    continue
                }
                r, why := checkVersion(critVer, m, f.Version)
                if r != "" && rank[r] > rank[best] {
                    best, note = r, why
                }
            }
        }
    }
    if best == "" {
        return "possible", "no machine-readable version range for " + f.Product + " — manual review advised"
    }
    return best, note
}

func parseCPE(name string) (vendor, product, version string, ok bool) {
    parts := strings.Split(name, ":")
    if len(parts) < 6 || parts[0] != "cpe" || parts[2] != "a" {
        return "", "", "", false // only CPE "application" parts are relevant here
    }
    return parts[3], parts[4], parts[5], true
}

func cpeBelongs(bases []string, vendor, product string) bool {
    for _, b := range bases {
        parts := strings.Split(b, ":")
        if len(parts) >= 5 &&
            strings.EqualFold(parts[3], vendor) &&
            strings.EqualFold(parts[4], product) {
            return true
        }
    }
    return false
}

func checkVersion(critVer string, m nvdCpeMatch, version string) (result, note string) {
    hasRange := m.VersionStartIncluding != "" || m.VersionStartExcluding != "" ||
        m.VersionEndIncluding != "" || m.VersionEndExcluding != ""
    if hasRange {
        ok := true
        var sb strings.Builder
        sb.WriteString("version ")
        sb.WriteString(version)
        if m.VersionStartIncluding != "" {
            sb.WriteString(" >= " + m.VersionStartIncluding)
            if vercmp(version, m.VersionStartIncluding) < 0 {
                ok = false
            }
        }
        if m.VersionStartExcluding != "" {
            sb.WriteString(" > " + m.VersionStartExcluding)
            if vercmp(version, m.VersionStartExcluding) <= 0 {
                ok = false
            }
        }
        if m.VersionEndIncluding != "" {
            sb.WriteString(" <= " + m.VersionEndIncluding)
            if vercmp(version, m.VersionEndIncluding) > 0 {
                ok = false
            }
        }
        if m.VersionEndExcluding != "" {
            sb.WriteString(" < " + m.VersionEndExcluding)
            if vercmp(version, m.VersionEndExcluding) >= 0 {
                ok = false
            }
        }
        if ok {
            return "likely", sb.String() + " satisfies the affected range"
        }
        return "unlikely", sb.String() + " is OUTSIDE the affected range"
    }
    critVer = strings.TrimSpace(critVer)
    switch {
    case critVer == "", critVer == "-", critVer == "*":
        return "possible", "criteria applies to all versions of the product"
    case vercmp(version, critVer) == 0:
        return "likely", "exact version match: " + version
    default:
        return "unlikely", version + " != affected version " + critVer
    }
}

// vercmp: natural ordering — numeric runs compare numerically, other runs
// lexically. Handles "1.18.0", "1.1.1k", "9.4.44.v20210927" well enough.
func vercmp(a, b string) int {
    a = strings.TrimPrefix(strings.TrimSpace(a), "v")
    b = strings.TrimPrefix(strings.TrimSpace(b), "v")
    ar, br := tokenRuns(a), tokenRuns(b)
    n := min(len(ar), len(br))
    for i := 0; i < n; i++ {
        an, aok := atoi(ar[i])
        bn, bok := atoi(br[i])
        if aok && bok {
            if an != bn {
                if an < bn {
                    return -1
                }
                return 1
            }
            continue
        }
        if c := strings.Compare(strings.ToLower(ar[i]), strings.ToLower(br[i])); c != 0 {
            return c
        }
    }
    return len(ar) - len(br)
}

func tokenRuns(s string) []string {
    var runs []string
    var cur []rune
    digitCur := false
    for _, r := range s {
        isD := r >= '0' && r <= '9'
        if len(cur) == 0 {
            cur = append(cur, r)
            digitCur = isD
            continue
        }
        if isD == digitCur {
            cur = append(cur, r)
        } else {
            runs = append(runs, string(cur))
            cur = []rune{r}
            digitCur = isD
        }
    }
    if len(cur) > 0 {
        runs = append(runs, string(cur))
    }
    return runs
}

func atoi(s string) (int, bool) {
    n, err := strconv.Atoi(s)
    if err != nil {
        return 0, false
    }
    return n, true
}

// ---------------------------------------------------------------------------
// field extractors
// ---------------------------------------------------------------------------

func description(c nvdCve) string {
    for _, d := range c.Descriptions {
        if d.Lang == "en" {
            return d.Value
        }
    }
    if len(c.Descriptions) > 0 {
        return c.Descriptions[0].Value
    }
    return ""
}

func severityOf(c nvdCve) (string, float64) {
    for _, m := range c.Metrics.CvssMetricV40 {
        return sevFrom(m)
    }
    for _, m := range c.Metrics.CvssMetricV31 {
        return sevFrom(m)
    }
    for _, m := range c.Metrics.CvssMetricV30 {
        return sevFrom(m)
    }
    for _, m := range c.Metrics.CvssMetricV2 {
        return sevFrom(m)
    }
    return "", 0
}

func sevFrom(m nvdMetric) (string, float64) {
    sev := m.CvssData.BaseSeverity
    if sev == "" {
        sev = m.BaseSeverity
    }
    return sev, m.CvssData.BaseScore
}

func cweOf(c nvdCve) []string {
    var out []string
    for _, w := range c.Weaknesses {
        for _, d := range w.Description {
            if strings.HasPrefix(d.Value, "CWE-") && !slices.Contains(out, d.Value) {
                out = append(out, d.Value)
            }
        }
    }
    return out
}

func refList(c nvdCve) []string {
    var out []string
    for _, r := range c.References {
        out = append(out, r.Url)
    }
    return out
}

// ---------------------------------------------------------------------------
// merge + sort across findings
// ---------------------------------------------------------------------------

func mergeCVEs(existing, add []CVE) []CVE {
    idx := make(map[string]int, len(existing))
    for i := range existing {
        idx[existing[i].ID] = i
    }
    for _, c := range add {
        if j, ok := idx[c.ID]; ok {
            e := &existing[j]
            if rankConfidence(c.Confidence) > rankConfidence(e.Confidence) {
                e.Confidence, e.MatchNote = c.Confidence, c.MatchNote
            }
            if c.CVSS > e.CVSS {
                e.CVSS, e.Severity = c.CVSS, c.Severity
            }
            for _, src := range c.Sources {
                if !slices.Contains(e.Sources, src) {
                    e.Sources = append(e.Sources, src)
                }
            }
        } else {
            idx[c.ID] = len(existing)
            existing = append(existing, c)
        }
    }
    return existing
}

func rankConfidence(c string) int {
    switch c {
    case "likely":
        return 2
    case "possible":
        return 1
    default:
        return 0
    }
}

func sortCVEs(cs []CVE) {
    sort.SliceStable(cs, func(i, j int) bool {
        if ri, rj := rankConfidence(cs[i].Confidence), rankConfidence(cs[j].Confidence); ri != rj {
            return ri > rj
        }
        if cs[i].CVSS != cs[j].CVSS {
            return cs[i].CVSS > cs[j].CVSS
        }
        return cs[i].ID < cs[j].ID
    })
}