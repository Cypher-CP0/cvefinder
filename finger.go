package main

import (
    "context"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "slices"
    "sort"
    "strings"
    "time"
)

// ---------------------------------------------------------------------------
// types
// ---------------------------------------------------------------------------

// Finding is one identified technology on the target.
type Finding struct {
    Product  string   `json:"product"`
    Category string   `json:"category"`
    Version  string   `json:"version,omitempty"`
    CPEs     []string `json:"cpes,omitempty"`    // CPE 2.3 name prefixes (no version), incl. aliases
    Keywords []string `json:"keywords,omitempty"` // used for NVD keywordSearch when no CPE / no version
    Evidence []string `json:"evidence"`
}

type scanOpts struct {
    probe   bool
    delay   time.Duration
    ua      string
    verbose bool
}

// matchRule is a compiled regex plus which capture group (if any) holds a version.
type matchRule struct {
    re   string
    ver  int // 1-based capture group with a version; 0 = presence only
    cre  *regexp.Regexp
}

type headerRule struct {
    header string
    rule   matchRule
}

type probeRule struct {
    path string // relative to the target path
    rule matchRule
}

type sig struct {
    product  string
    category string
    cpe      string   // primary CPE prefix, e.g. "cpe:2.3:a:apache:http_server"
    aliases  []string // alternates NVD may use for the same product
    keywords []string
    headers  []headerRule // matched against response headers (case-insensitive lookups)
    cookies  []matchRule // matched against "name=value; name2=value2" from Set-Cookie
    body     []matchRule // matched against the response body (HTML/JSON)
    probes   []probeRule // extra GETs to well-known paths
}

// ---------------------------------------------------------------------------
// signature database — extend this table to teach the tool new products
// ---------------------------------------------------------------------------

var signatures = []*sig{
    // ------------------------- web servers -------------------------
    {
        product: "Apache HTTP Server", category: "Server",
        cpe: "cpe:2.3:a:apache:http_server", keywords: []string{"Apache httpd"},
        headers: []headerRule{
            {header: "Server", rule: matchRule{re: `(?i)^Apache(?:-HTTPD)?/([0-9][0-9a-zA-Z.]+)`, ver: 1}},
            {header: "Server", rule: matchRule{re: `(?i)^Apache(?:-HTTPD)?(?:$|\s|\()`}},
        },
    },
    {
        product: "nginx", category: "Server",
        cpe: "cpe:2.3:a:f5:nginx", aliases: []string{"cpe:2.3:a:nginx:nginx"}, keywords: []string{"nginx"},
        headers: []headerRule{
            {header: "Server", rule: matchRule{re: `(?i)^nginx/([0-9][0-9a-zA-Z.]+)`, ver: 1}},
            {header: "Server", rule: matchRule{re: `(?i)^nginx(?:$|\s)`}},
        },
    },
    {
        product: "Microsoft IIS", category: "Server",
        cpe: "cpe:2.3:a:microsoft:internet_information_services",
        aliases: []string{"cpe:2.3:a:microsoft:internet_information_server"},
        keywords: []string{"Internet Information Services"},
        headers: []headerRule{
            {header: "Server", rule: matchRule{re: `(?i)^Microsoft-IIS/([0-9.]+)`, ver: 1}},
        },
    },
    {
        product: "Apache Tomcat", category: "Server",
        cpe: "cpe:2.3:a:apache:tomcat", keywords: []string{"Apache Tomcat"},
        headers: []headerRule{
            // Coyote is the connector name, NOT the Tomcat version — presence only
            {header: "Server", rule: matchRule{re: `(?i)^Apache-Coyote/`}},
        },
        cookies: []matchRule{{re: `(?i)(?:^|;\s*)JSESSIONID=`}},
        body: []matchRule{
            // default error pages leak the real version (picked up via the 404 probe)
            {re: `(?i)Apache\s+Tomcat(?:/|\s+v(?:ersion)?\s*)([0-9][0-9.]*)?`, ver: 1},
        },
    },
    {
        product: "Eclipse Jetty", category: "Server",
        cpe: "cpe:2.3:a:eclipse:jetty", keywords: []string{"Jetty"},
        headers: []headerRule{
            {header: "Server", rule: matchRule{re: `(?i)^Jetty\(([0-9][0-9A-Za-z.]*)\)`, ver: 1}},
            {header: "Server", rule: matchRule{re: `(?i)^Jetty`}},
        },
    },
    {
        product: "LiteSpeed Web Server", category: "Server",
        keywords: []string{"LiteSpeed"},
        headers: []headerRule{
            {header: "Server", rule: matchRule{re: `(?i)^LiteSpeed(?:/([0-9.]+))?`, ver: 1}},
        },
    },

    // --------------------- languages & runtimes ---------------------
    {
        product: "PHP", category: "Language runtime",
        cpe: "cpe:2.3:a:php:php", keywords: []string{"PHP"},
        headers: []headerRule{
            {header: "X-Powered-By", rule: matchRule{re: `(?i)\bPHP/([0-9][0-9A-Za-z.+-]*)`, ver: 1}},
            {header: "X-Powered-By", rule: matchRule{re: `(?i)^PHP\b`}},
            {header: "Server", rule: matchRule{re: `(?i)\bPHP/([0-9][0-9A-Za-z.+-]*)`, ver: 1}},
        },
    },
    {
        product: "OpenSSL", category: "Library",
        cpe: "cpe:2.3:a:openssl:openssl", keywords: []string{"OpenSSL"},
        headers: []headerRule{
            {header: "Server", rule: matchRule{re: `(?i)OpenSSL/([0-9][0-9a-zA-Z.+-]*)`, ver: 1}},
        },
    },

    // ---------------------------- CMSs ------------------------------
    {
        product: "WordPress", category: "CMS",
        cpe: "cpe:2.3:a:wordpress:wordpress", keywords: []string{"WordPress"},
        body: []matchRule{
            {re: `(?i)<meta[^>]+name=["']generator["'][^>]+content=["']WordPress(?:\s+([0-9][0-9.]*))?`, ver: 1},
            {re: `(?i)/(?:wp-content|wp-includes|wp-json)/`},
        },
        probes: []probeRule{
            {path: "wp-login.php", rule: matchRule{re: `(?i)wp-login\.php`}},
            {path: "readme.html", rule: matchRule{re: `(?i)Version\s+([0-9][0-9.]+)`, ver: 1}},
        },
    },
    {
        product: "Joomla", category: "CMS",
        cpe: "cpe:2.3:a:joomla:joomla", keywords: []string{"Joomla"},
        body: []matchRule{
            {re: `(?i)<meta[^>]+name=["']generator["'][^>]+content=["']Joomla!?\s*([0-9.]*)?`, ver: 1},
            {re: `(?i)media/(?:jui|system)/`},
        },
        probes: []probeRule{
            // classic recon trick: the manifest leaks the exact version
            {path: "administrator/manifests/files/joomla.xml", rule: matchRule{re: `<version>([0-9][0-9.]*)</version>`, ver: 1}},
        },
    },
    {
        product: "Drupal", category: "CMS",
        cpe: "cpe:2.3:a:drupal:drupal", keywords: []string{"Drupal"},
        headers: []headerRule{
            {header: "X-Drupal-Cache", rule: matchRule{re: `.`}},
            {header: "X-Generator", rule: matchRule{re: `(?i)\bDrupal\s+([0-9][0-9.x]*)`, ver: 1}},
        },
        body: []matchRule{
            {re: `(?i)<meta[^>]+name=["']generator["'][^>]+content=["']Drupal\s+([0-9]+)`, ver: 1},
            {re: `(?i)/sites/(?:default|all)/files`},
        },
        probes: []probeRule{
            {path: "CHANGELOG.txt", rule: matchRule{re: `(?i)Drupal\s+([0-9][0-9.x-]*),`, ver: 1}},
        },
    },
    {
        product: "Magento", category: "E-commerce",
        cpe: "cpe:2.3:a:magento:magento", keywords: []string{"Magento"},
        cookies: []matchRule{{re: `(?i)(?:^|;\s*)X-Magento-Vary=`}},
        body: []matchRule{{re: `(?i)(?:data-mage-init|js/mage/|Magento_[A-Za-z]+)`}},
    },
    {
        product: "Ghost", category: "CMS",
        cpe: "cpe:2.3:a:ghost:ghost", keywords: []string{"Ghost"},
        headers: []headerRule{{header: "X-Powered-By", rule: matchRule{re: `(?i)\bGhost\b`}}},
    },
    {
        product: "phpMyAdmin", category: "Application",
        cpe: "cpe:2.3:a:phpmyadmin:phpmyadmin", keywords: []string{"phpMyAdmin"},
        body: []matchRule{
            {re: `(?i)phpMyAdmin\s+([0-9][0-9.]*)`, ver: 1},
            {re: `(?i)phpMyAdmin\b`},
        },
        probes: []probeRule{
            {path: "phpmyadmin/", rule: matchRule{re: `(?i)phpMyAdmin\b`}},
            {path: "pma/", rule: matchRule{re: `(?i)phpMyAdmin\b`}},
        },
    },

    // -------------------------- frameworks --------------------------
    {
        product: "Microsoft ASP.NET", category: "Framework",
        cpe: "cpe:2.3:a:microsoft:asp.net", keywords: []string{"ASP.NET"},
        headers: []headerRule{
            {header: "X-AspNet-Version", rule: matchRule{re: `^([0-9.]+)`, ver: 1}}, // runtime version, approximate
            {header: "X-Powered-By", rule: matchRule{re: `(?i)^ASP\.NET`}},
        },
    },
    {
        product: "ASP.NET MVC", category: "Framework",
        cpe: "cpe:2.3:a:microsoft:asp.net_mvc", keywords: []string{"ASP.NET MVC"},
        headers: []headerRule{
            {header: "X-AspNetMvc-Version", rule: matchRule{re: `^([0-9.]+)`, ver: 1}},
        },
    },
    {
        product: "Django", category: "Framework",
        cpe: "cpe:2.3:a:djangoproject:django", keywords: []string{"Django"},
        cookies: []matchRule{{re: `(?i)(?:^|;\s*)csrftoken=`}},
        probes: []probeRule{
            {path: "admin/login/", rule: matchRule{re: `(?i)csrfmiddlewaretoken`}},
        },
    },
    {
        product: "Laravel", category: "Framework",
        cpe: "cpe:2.3:a:laravel:laravel", keywords: []string{"Laravel"},
        cookies: []matchRule{{re: `(?i)(?:^|;\s*)laravel_session=`}},
    },
    {
        product: "Ruby on Rails / Rack", category: "Framework",
        cpe: "cpe:2.3:a:rubyonrails:rails", keywords: []string{"Rails"},
        headers: []headerRule{
            {header: "X-Runtime", rule: matchRule{re: `^[0-9.]+$`}},
        },
    },
    {
        product: "Express (Node.js)", category: "Framework",
        cpe: "cpe:2.3:a:expressjs:express", keywords: []string{"Express"},
        headers: []headerRule{{header: "X-Powered-By", rule: matchRule{re: `(?i)^Express\b`}}},
    },
    {
        product: "Spring Framework / Spring Boot", category: "Framework",
        cpe: "cpe:2.3:a:vmware:spring_framework", aliases: []string{"cpe:2.3:a:pivotal:spring_framework"},
        keywords: []string{"Spring Framework"},
        headers: []headerRule{
            {header: "X-Application-Context", rule: matchRule{re: `.`}}, // Spring Boot 1.x
        },
        body: []matchRule{
            // the whitelabel error page — picked up via the 404 probe
            {re: `(?i)Whitelabel\s+Error\s+Page`},
        },
    },
    {
        product: "Next.js", category: "Framework",
        cpe: "cpe:2.3:a:vercel:next.js", keywords: []string{"Next.js"},
        body: []matchRule{
            {re: `(?i)__NEXT_DATA__`},
            {re: `(?i)/_next/static/`},
        },
    },
    {
        product: "Strapi", category: "Application",
        keywords: []string{"Strapi"},
        headers: []headerRule{{header: "X-Powered-By", rule: matchRule{re: `(?i)\bStrapi\b`}}},
    },

    // --------------------- client-side libraries --------------------
    {
        product: "jQuery", category: "JavaScript library",
        cpe: "cpe:2.3:a:jquery:jquery", keywords: []string{"jQuery"},
        body: []matchRule{
            {re: `(?i)jquery(?:\.min)?\.js\?ver=([0-9][0-9a-zA-Z.-]*)`, ver: 1}, // WordPress style
            {re: `(?i)jquery-([0-9][0-9.]*[0-9a-zA-Z]*)(?:\.min)?\.js`, ver: 1},  // CDN style
            {re: `(?i)jquery(?:[-.][0-9a-z.]*)?\.js`},
        },
    },
    {
        product: "Angular", category: "JavaScript framework",
        cpe: "cpe:2.3:a:google:angular", keywords: []string{"Angular"},
        body: []matchRule{
            {re: `(?i)ng-version=["']([0-9][0-9.]*)`, ver: 1},
        },
    },

    // ------------------------ infrastructure ------------------------
    {
        product: "Varnish Cache", category: "Reverse proxy",
        cpe: "cpe:2.3:a:varnishcache:varnish_cache", keywords: []string{"Varnish"},
        headers: []headerRule{
            {header: "X-Varnish", rule: matchRule{re: `[0-9]`}},
            {header: "Via", rule: matchRule{re: `(?i)\bvarnish\b`}},
            {header: "X-Varnish-Version", rule: matchRule{re: `(?i)varnish/([0-9.]+)`, ver: 1}},
        },
    },
    {
        product: "Jenkins", category: "CI/CD",
        cpe: "cpe:2.3:a:jenkins:jenkins", keywords: []string{"Jenkins"},
        headers: []headerRule{
            {header: "X-Jenkins", rule: matchRule{re: `^([0-9][0-9.]*)`, ver: 1}},
        },
    },
}

// compile all signature regexes once at startup
func init() {
    for _, s := range signatures {
        for i := range s.headers {
            s.headers[i].rule.cre = regexp.MustCompile(s.headers[i].rule.re)
        }
        for i := range s.cookies {
            s.cookies[i].cre = regexp.MustCompile(s.cookies[i].re)
        }
        for i := range s.body {
            s.body[i].cre = regexp.MustCompile(s.body[i].re)
        }
        for i := range s.probes {
            s.probes[i].rule.cre = regexp.MustCompile(s.probes[i].rule.re)
        }
    }
}

// ---------------------------------------------------------------------------
// engine
// ---------------------------------------------------------------------------

type matchCtx struct {
    body    string
    cookies string
    header  http.Header
}

func fetch(ctx context.Context, c *http.Client, u *url.URL, opts scanOpts) (*http.Response, string, error) {
    t0 := time.Now()
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
    if err != nil {
        return nil, "", err
    }
    req.Header.Set("User-Agent", opts.ua)
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
    resp, err := c.Do(req)
    if err != nil {
        return nil, "", err
    }
    defer resp.Body.Close()
    b, rerr := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2 MB cap per page
    if opts.verbose {
        fmt.Fprintf(os.Stderr, "    GET %s -> %d (%s)\n", u.String(), resp.StatusCode, time.Since(t0).Round(time.Millisecond))
    }
    if rerr != nil {
        return resp, "", rerr
    }
    return resp, string(b), nil
}

func cookieString(resp *http.Response) string {
    var sb strings.Builder
    for i, ck := range resp.Cookies() {
        if i > 0 {
            sb.WriteString("; ")
        }
        sb.WriteString(ck.Name + "=" + ck.Value)
    }
    return sb.String()
}

func (s *sig) match(m matchCtx, ev *[]string) (version string, hit bool) {
    for _, hr := range s.headers {
        v := m.header.Get(hr.header)
        if v == "" {
            continue
        }
        sub := hr.rule.cre.FindStringSubmatch(v)
        if sub == nil {
            continue
        }
        hit = true
        *ev = append(*ev, fmt.Sprintf("%s: %q", hr.header, truncate(v, 70)))
        if version == "" && hr.rule.ver > 0 && len(sub) > hr.rule.ver && sub[hr.rule.ver] != "" {
            version = cleanVersion(sub[hr.rule.ver])
        }
    }
    if m.cookies != "" {
        for _, cr := range s.cookies {
            sub := cr.cre.FindStringSubmatch(m.cookies)
            if sub == nil {
                continue
            }
            hit = true
            *ev = append(*ev, "cookie: "+truncate(sub[0], 40))
            if version == "" && cr.ver > 0 && len(sub) > cr.ver && sub[cr.ver] != "" {
                version = cleanVersion(sub[cr.ver])
            }
        }
    }
    if m.body != "" {
        for _, br := range s.body {
            sub := br.cre.FindStringSubmatch(m.body)
            if sub == nil {
                continue
            }
            hit = true
            *ev = append(*ev, fmt.Sprintf("body: %q", truncate(sub[0], 60)))
            if version == "" && br.ver > 0 && len(sub) > br.ver && sub[br.ver] != "" {
                version = cleanVersion(sub[br.ver])
            }
        }
    }
    return version, hit
}

func fingerprint(ctx context.Context, client *http.Client, target *url.URL, opts scanOpts) ([]Finding, int, error) {
    rootResp, body, err := fetch(ctx, client, target, opts)
    if err != nil {
        return nil, 0, fmt.Errorf("target request failed: %w", err)
    }
    requests := 1

    results := map[string]*Finding{}

    record := func(s *sig, version string, ev []string) {
        f, ok := results[s.product]
        if !ok {
            f = &Finding{Product: s.product, Category: s.category, Keywords: s.keywords}
            if s.cpe != "" {
                f.CPEs = append(f.CPEs, s.cpe)
                f.CPEs = append(f.CPEs, s.aliases...)
            }
            results[s.product] = f
        }
        if version != "" && f.Version == "" {
            f.Version = version
        }
        for _, e := range ev {
            if !slices.Contains(f.Evidence, e) {
                f.Evidence = append(f.Evidence, e)
            }
        }
    }

    run := func(m matchCtx) {
        for _, s := range signatures {
            var ev []string
            version, hit := s.match(m, &ev)
            if hit {
                record(s, version, ev)
            }
        }
    }

    run(matchCtx{body: body, cookies: cookieString(rootResp), header: rootResp.Header})

    if opts.probe {
        // 1) a random 404 page — error pages leak versions (Tomcat, Spring, PHP...)
        fourOhFour := *target
        fourOhFour.Path = strings.TrimSuffix(target.Path, "/") + "/cvefinder-" + randomSuffix()
        fourOhFour.RawQuery = ""
        if resp, b, ferr := fetch(ctx, client, &fourOhFour, opts); ferr == nil {
            requests++
            run(matchCtx{body: b, cookies: cookieString(resp), header: resp.Header})
        }
        sleep(opts.delay)

        // 2) per-signature probes to well-known paths
        for _, s := range signatures {
            for _, p := range s.probes {
                if ctx.Err() != nil {
                    return finalize(results), requests, nil
                }
                pu := *target
                pu.Path = strings.TrimSuffix(target.Path, "/") + "/" + p.path
                pu.RawQuery = ""
                resp, b, ferr := fetch(ctx, client, &pu, opts)
                requests++
                if ferr != nil {
                    continue
                }
                if sub := p.rule.cre.FindStringSubmatch(b); sub != nil {
                    version := ""
                    if p.rule.ver > 0 && len(sub) > p.rule.ver && sub[p.rule.ver] != "" {
                        version = cleanVersion(sub[p.rule.ver])
                    }
                    record(s, version, []string{fmt.Sprintf("%s: %q", p.path, truncate(sub[0], 50))})
                }
                sleep(opts.delay)
            }
        }
    }
    return finalize(results), requests, nil
}

func finalize(m map[string]*Finding) []Finding {
    out := make([]Finding, 0, len(m))
    for _, f := range m {
        out = append(out, *f)
    }
    sort.Slice(out, func(i, j int) bool {
        if out[i].Category != out[j].Category {
            return out[i].Category < out[j].Category
        }
        return out[i].Product < out[j].Product
    })
    return out
}

func cleanVersion(v string) string {
    v = strings.TrimSpace(v)
    v = strings.TrimPrefix(v, "v")
    return strings.TrimRight(v, ".-_")
}

func truncate(s string, n int) string {
    if len(s) > n {
        return s[:n] + "…"
    }
    return s
}

func randomSuffix() string {
    return fmt.Sprintf("%d", time.Now().UnixNano()%1e6)
}

func sleep(d time.Duration) {
    if d > 0 {
        time.Sleep(d)
    }
}