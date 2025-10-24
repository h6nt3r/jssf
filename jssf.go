package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// --- ANSI Color Codes ---
const (
	colorGoldenBrown = "\033[38;2;138;116;10m"
	colorReset       = "\033[0m"
)

// --- Flags ---
var (
	flagURL     = flag.String("u", "", "Scan a single URL (http[s]://...)")
	flagFile    = flag.String("f", "", "Scan a file (each line is a URL)")
	flagSecret  = flag.Bool("secret", false, "Detect secret patterns using regex (from patterns.go)")
	flagLinks   = flag.Bool("links", false, "Extract in-scope links (relative + absolute)")
	flagSubs    = flag.Bool("subs", false, "Extract only subdomains for the target's root domain (exclusive with -links)")
	flagPath    = flag.Bool("path", false, "Extract file system paths (absolute, relative, home-relative)")
	flagCustom  = flag.String("custom", "", "Custom mode: comma-separated list of modes (links,path,secret,subs)")
	flagOutfile = flag.String("o", "", "Save output to plain text file (optional)")
	flagTimeout = flag.Int("timeout", 5, "HTTP request timeout in seconds")
	flagThread  = flag.Int("thread", 5, "Number of concurrent threads")
	flagExclude = flag.String("exclude", "", "Comma-separated list of extensions to exclude (e.g. png,jpg,svg)")
	flagSilent  = flag.Bool("s", false, "Silent mode (hide banner and summary)")
	flagHelp    = flag.Bool("h", false, "Show help")
)

// --- Helper: expand ~ ---
func expandPath(p string) string {
	if strings.HasPrefix(p, "~") {
		usr, err := user.Current()
		if err == nil {
			return filepath.Join(usr.HomeDir, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// --- Helper: root domain extraction ---
func getRootDomain(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return host
}

// --- Regex for ANSI color removal ---
var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}

// --- Exclude logic ---
func shouldExclude(target string, excluded []string) bool {
	lower := strings.ToLower(target)
	for _, e := range excluded {
		if e == "" {
			continue
		}
		pattern := "." + strings.TrimPrefix(e, ".")
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// --- Link extraction regex ---
var linkRegex = regexp.MustCompile(`(?i)(?:href|src|url|action)\s*=\s*["']([^"'>\s]+)["']|fetch\(["']([^"']+)["']\)`)

type linkItem struct {
	URL  string
	Type string
}

func extractLinks(content, base, rootDomain string, excludedExts []string) []linkItem {
	matches := linkRegex.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	var links []linkItem

	for _, m := range matches {
		link := ""
		if m[1] != "" {
			link = m[1]
		} else if len(m) > 2 && m[2] != "" {
			link = m[2]
		}
		if link == "" {
			continue
		}

		u, err := url.Parse(link)
		if err != nil {
			continue
		}
		baseURL, _ := url.Parse(base)
		full := baseURL.ResolveReference(u).String()

		if shouldExclude(full, excludedExts) {
			continue
		}

		linkType := "Relative"
		if u.IsAbs() {
			linkType = "Absolute"
		}

		if strings.Contains(full, rootDomain) && !seen[full] {
			seen[full] = true
			links = append(links, linkItem{URL: full, Type: linkType})
		}
	}
	return links
}

// --- Extract file system paths ---
var pathRegex = regexp.MustCompile(`(?m)(?:["'\s]|^)(~\/[^\s"'<>]+|\/[A-Za-z0-9._\-/]+|(?:\.\.?\/)[A-Za-z0-9._\-/]+)(?:["'\s]|$)`)

type pathItem struct {
	Path string
	Type string
}

func extractPaths(content string, excludedExts []string) []pathItem {
	matches := pathRegex.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	var paths []pathItem

	for _, m := range matches {
		p := strings.TrimSpace(m[1])
		if p == "" || seen[p] {
			continue
		}
		if shouldExclude(p, excludedExts) {
			continue
		}
		seen[p] = true

		pType := "Relative"
		if strings.HasPrefix(p, "/") {
			pType = "Absolute"
		}
		paths = append(paths, pathItem{Path: p, Type: pType})
	}
	return paths
}

// --- Extract subdomains ---
func extractSubdomains(content, base, rootDomain string) []string {
	matches := linkRegex.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	var subs []string
	for _, m := range matches {
		link := ""
		if m[1] != "" {
			link = m[1]
		} else if len(m) > 2 && m[2] != "" {
			link = m[2]
		}
		if link == "" {
			continue
		}
		u, err := url.Parse(link)
		if err != nil {
			continue
		}
		baseURL, _ := url.Parse(base)
		full := baseURL.ResolveReference(u)
		h := full.Hostname()
		if h == "" {
			continue
		}
		if h == rootDomain {
			continue
		}
		if strings.HasSuffix(h, "."+rootDomain) {
			if !seen[h] {
				seen[h] = true
				subs = append(subs, h)
			}
		}
	}
	return subs
}

// --- Fetch content ---
func fetchURL(target string) (string, int, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: time.Duration(*flagTimeout) * time.Second}
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "jssf/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

// --- Compile patterns (from patterns.go) ---
type compiledPattern struct {
	Name string
	Re   *regexp.Regexp
}

func compilePatterns() []compiledPattern {
	var compiled []compiledPattern
	for name, pattern := range RegexPatterns {
		re, err := regexp.Compile("(?m)" + pattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to compile pattern %s: %v\n", name, err)
			continue
		}
		compiled = append(compiled, compiledPattern{Name: name, Re: re})
	}
	return compiled
}

type matchResult struct {
	PatternName string
	Match       string
}

func scanText(text string, compiled []compiledPattern) []matchResult {
	results := []matchResult{}
	for _, cp := range compiled {
		matches := cp.Re.FindAllString(text, -1)
		for _, m := range matches {
			results = append(results, matchResult{PatternName: cp.Name, Match: m})
		}
	}
	return results
}

// --- Read URLs from file ---
func readLines(path string) ([]string, error) {
	path = expandPath(path)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		s := strings.TrimSpace(scanner.Text())
		if s != "" {
			lines = append(lines, s)
		}
	}
	return lines, scanner.Err()
}

// --- Main ---
func main() {
	flag.Parse()
	if *flagHelp {
		flag.Usage()
		return
	}

	if *flagCustom != "" && (*flagLinks || *flagSubs || *flagPath || *flagSecret) {
		fmt.Fprintln(os.Stderr, "[!] Error: -custom cannot be used with -links, -subs, -path, or -secret")
		return
	}

	customModes := make(map[string]bool)
	if *flagCustom != "" {
		modes := strings.Split(strings.ToLower(*flagCustom), ",")
		for _, mode := range modes {
			mode = strings.TrimSpace(mode)
			if mode == "links" || mode == "subs" || mode == "path" || mode == "secret" {
				customModes[mode] = true
			} else {
				fmt.Fprintf(os.Stderr, "[!] Invalid custom mode: %s\n", mode)
				return
			}
		}
	}

	var excludedExts []string
	if *flagExclude != "" {
		for _, e := range strings.Split(*flagExclude, ",") {
			e = strings.ToLower(strings.TrimSpace(e))
			if e != "" {
				excludedExts = append(excludedExts, e)
			}
		}
	}

	var f *os.File
	saveToFile := false
	if *flagOutfile != "" {
		p := expandPath(*flagOutfile)
		file, err := os.Create(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Cannot create file %s: %v\n", p, err)
			return
		}
		f = file
		defer f.Close()
		saveToFile = true
	}

	if !*flagSilent {
		fmt.Println("Javascript Secret Finder. Current version 2.0.1")
		fmt.Println("Developed by github.com/h6nt3r\n")
	}

	var targets []string
	if *flagURL != "" {
		targets = append(targets, *flagURL)
	} else if *flagFile != "" {
		lines, err := readLines(*flagFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] File read error: %v\n", err)
			return
		}
		targets = append(targets, lines...)
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			sc := bufio.NewScanner(os.Stdin)
			for sc.Scan() {
				t := strings.TrimSpace(sc.Text())
				if t != "" {
					targets = append(targets, t)
				}
			}
		} else {
			fmt.Fprintln(os.Stderr, "No input provided. Use -u, -f, or pipe input.")
			return
		}
	}

	compiled := []compiledPattern{}
	if *flagSecret || customModes["secret"] {
		compiled = compilePatterns()
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, *flagThread)
	resultsCh := make(chan string, len(targets))
	var totalErrors int64
	start := time.Now()

	uniqueFound := make(map[string]bool)
	var mu sync.Mutex

	for i, t := range targets {
		index := i + 1
		target := t
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			body, _, err := fetchURL(target)
			if err != nil {
				atomic.AddInt64(&totalErrors, 1)
				return
			}

			root := getRootDomain(target)
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("URL(%d/%d): %s\n", index, len(targets), target))

			if *flagLinks || customModes["links"] {
				for i, l := range extractLinks(body, target, root, excludedExts) {
					key := "link:" + l.URL
					mu.Lock()
					if !uniqueFound[key] {
						uniqueFound[key] = true
						colored := fmt.Sprintf("%s%s%s", colorGoldenBrown, l.URL, colorReset)
						sb.WriteString(fmt.Sprintf("Link-%s(%d): %s\n", l.Type, i+1, colored))
					}
					mu.Unlock()
				}
			}

			if *flagPath || customModes["path"] {
				for i, p := range extractPaths(body, excludedExts) {
					key := "path:" + p.Path
					mu.Lock()
					if !uniqueFound[key] {
						uniqueFound[key] = true
						colored := fmt.Sprintf("%s%s%s", colorGoldenBrown, p.Path, colorReset)
						sb.WriteString(fmt.Sprintf("Path-%s(%d): %s\n", p.Type, i+1, colored))
					}
					mu.Unlock()
				}
			}

			if *flagSubs || customModes["subs"] {
				for i, s := range extractSubdomains(body, target, root) {
					mu.Lock()
					if !uniqueFound[s] {
						uniqueFound[s] = true
						colored := fmt.Sprintf("%s%s%s", colorGoldenBrown, s, colorReset)
						sb.WriteString(fmt.Sprintf("Subdomain(%d): %s\n", i+1, colored))
					}
					mu.Unlock()
				}
			}

			if *flagSecret || customModes["secret"] {
				for _, m := range scanText(body, compiled) {
					key := m.PatternName + ":" + m.Match
					mu.Lock()
					if !uniqueFound[key] {
						uniqueFound[key] = true
						colored := fmt.Sprintf("%s%s%s", colorGoldenBrown, m.Match, colorReset)
						sb.WriteString(fmt.Sprintf("%s -> %s\n", strings.ToLower(m.PatternName), colored))
					}
					mu.Unlock()
				}
			}

			if sb.Len() > len(fmt.Sprintf("URL(%d/%d): %s\n", index, len(targets), target)) {
				resultsCh <- sb.String()
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	for res := range resultsCh {
		fmt.Print(res)
		if saveToFile && f != nil {
			f.WriteString(stripANSI(res))
		}
	}

	if !*flagSilent {
		duration := time.Since(start)
		minutes := int(duration.Minutes())
		seconds := int(duration.Seconds()) - minutes*60

		mu.Lock()
		totalUnique := len(uniqueFound)
		mu.Unlock()

		fmt.Printf("\nTotal links/path/secret/subs Found: %d\n", totalUnique)
		fmt.Printf("Total Error: %d\n", atomic.LoadInt64(&totalErrors))
		fmt.Printf("Total Time Taken: %d Minute %d Second\n", minutes, seconds)
	}
}
