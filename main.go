package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	sourceURL := flag.String("url", "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt", "URL with config lines")
	outputFile := flag.String("out", "live_50.txt", "output file path")
	limit := flag.Int("limit", 50, "how many live lines to save")
	workers := flag.Int("workers", 6, "parallel checks through Xray")
	xrayBin := flag.String("xray-bin", "xray", "path to xray binary")
	testURL := flag.String("test-url", "http://www.gstatic.com/generate_204", "url requested through xray proxy")
	startupTimeout := flag.Duration("startup-timeout", 1500*time.Millisecond, "xray startup wait time")
	requestTimeout := flag.Duration("request-timeout", 8*time.Second, "HTTP request timeout through xray")
	maxLatency := flag.Duration("max-latency", 3*time.Second, "max acceptable proxy response time")
	flag.Parse()

	if _, err := exec.LookPath(*xrayBin); err != nil {
		exitWithError(fmt.Errorf("xray not found (%s): %w", *xrayBin, err))
	}
	fmt.Printf("Using xray binary: %s\n", *xrayBin)
	fmt.Printf("Downloading configs from: %s\n", *sourceURL)

	lines, err := downloadLines(*sourceURL)
	if err != nil {
		exitWithError(err)
	}
	fmt.Printf("Loaded %d candidate lines\n", len(lines))
	fmt.Printf("Checking via Xray with %d workers (target: %d live)\n", *workers, *limit)
	fmt.Printf("Speed filter: response must be <= %s\n", maxLatency.String())

	opts := probeOptions{
		xrayBin:        *xrayBin,
		testURL:        *testURL,
		startupTimeout: *startupTimeout,
		requestTimeout: *requestTimeout,
		maxLatency:     *maxLatency,
	}
	live := collectLive(lines, *limit, *workers, opts)
	if len(live) == 0 {
		exitWithError(errors.New("live lines not found"))
	}

	if err := os.WriteFile(*outputFile, []byte(strings.Join(live, "\n")+"\n"), 0o644); err != nil {
		exitWithError(fmt.Errorf("write output: %w", err))
	}

	fmt.Printf("Saved %d live lines to %s\n", len(live), *outputFile)
}

func downloadLines(rawURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download source: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	var lines []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read source: %w", err)
	}

	return lines, nil
}

type probeOptions struct {
	xrayBin        string
	testURL        string
	startupTimeout time.Duration
	requestTimeout time.Duration
	maxLatency     time.Duration
}

func collectLive(lines []string, limit int, workers int, opts probeOptions) []string {
	if limit <= 0 || workers <= 0 {
		return nil
	}
	total := len(lines)

	type job struct {
		line string
	}
	jobs := make(chan job)
	results := make(chan string, limit)
	stop := make(chan struct{})
	var stopOnce sync.Once

	var wg sync.WaitGroup
	liveCount := 0
	var countMu sync.Mutex
	var checkedCount atomic.Int64
	startedAt := time.Now()

	progressDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				checked := int(checkedCount.Load())
				liveNow := 0
				countMu.Lock()
				liveNow = liveCount
				countMu.Unlock()
				fmt.Printf("\r%s", renderProgress(checked, total, liveNow, limit, startedAt))
			case <-progressDone:
				return
			}
		}
	}()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				live := checkLineWithXray(j.line, opts)
				checkedCount.Add(1)
				if !live {
					continue
				}
				countMu.Lock()
				if liveCount < limit {
					liveCount++
					results <- j.line
					fmt.Printf("\n[+] Live found %d/%d\n", liveCount, limit)
					if liveCount == limit {
						stopOnce.Do(func() { close(stop) })
					}
				}
				countMu.Unlock()
			}
		}()
	}

	go func() {
	dispatch:
		for _, line := range lines {
			select {
			case <-stop:
				break dispatch
			default:
			}
			select {
			case <-stop:
				break dispatch
			case jobs <- job{line: line}:
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
		close(progressDone)
	}()

	live := make([]string, 0, limit)
	for line := range results {
		live = append(live, line)
	}
	checked := int(checkedCount.Load())
	fmt.Printf("\r%s\n", renderProgress(checked, total, len(live), limit, startedAt))

	return live
}

func renderProgress(checked, total, live, limit int, startedAt time.Time) string {
	const barWidth = 28
	if total <= 0 {
		total = 1
	}
	if checked > total {
		checked = total
	}
	filled := (checked * barWidth) / total
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("#", filled) + strings.Repeat("-", barWidth-filled)
	percent := (checked * 100) / total
	elapsed := time.Since(startedAt).Round(time.Second)
	return fmt.Sprintf("Progress [%s] %3d%% checked:%d/%d live:%d/%d elapsed:%s", bar, percent, checked, total, live, limit, elapsed)
}

func checkLineWithXray(line string, opts probeOptions) bool {
	outbound, ok := buildOutbound(line)
	if !ok {
		return false
	}

	httpPort, err := freeTCPPort()
	if err != nil {
		return false
	}

	cfg := buildXrayConfig(outbound, httpPort)
	cfgData, err := json.Marshal(cfg)
	if err != nil {
		return false
	}

	tmp, err := os.CreateTemp("", "xray-check-*.json")
	if err != nil {
		return false
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(cfgData); err != nil {
		_ = tmp.Close()
		return false
	}
	_ = tmp.Close()

	var stderr bytes.Buffer
	cmd := exec.Command(opts.xrayBin, "run", "-c", tmpPath)
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return false
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-time.After(opts.startupTimeout):
	case <-done:
		return false
	}

	ok, latency := probeProxyHTTP(httpPort, opts.testURL, opts.requestTimeout)
	terminate(cmd, done)
	if !ok {
		return false
	}
	return latency <= opts.maxLatency
}

func terminate(cmd *exec.Cmd, done chan error) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func probeProxyHTTP(httpPort int, testURL string, timeout time.Duration) (bool, time.Duration) {
	proxyAddr := fmt.Sprintf("http://127.0.0.1:%d", httpPort)
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return false, 0
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, testURL, nil)
	if err != nil {
		return false, 0
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()
	latency := time.Since(start)
	return resp.StatusCode >= 200 && resp.StatusCode < 400, latency
}

func buildOutbound(line string) (map[string]any, bool) {
	switch {
	case strings.HasPrefix(line, "vmess://"):
		return buildVMessOutbound(line)
	case strings.HasPrefix(line, "vless://"):
		return buildVLESSOutbound(line)
	case strings.HasPrefix(line, "trojan://"):
		return buildTrojanOutbound(line)
	case strings.HasPrefix(line, "ss://"):
		return buildSSOutbound(line)
	default:
		return nil, false
	}
}

func buildVLESSOutbound(line string) (map[string]any, bool) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, false
	}
	userID := u.User.Username()
	host, port, ok := getHostPort(u)
	if !ok || userID == "" {
		return nil, false
	}

	q := u.Query()
	user := map[string]any{
		"id":         userID,
		"encryption": pickFirst(q.Get("encryption"), "none"),
	}
	if flow := q.Get("flow"); flow != "" {
		user["flow"] = flow
	}

	return map[string]any{
		"tag":      "proxy",
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []map[string]any{
				{
					"address": host,
					"port":    port,
					"users":   []map[string]any{user},
				},
			},
		},
		"streamSettings": buildStreamSettings(q, u.Fragment),
	}, true
}

func buildTrojanOutbound(line string) (map[string]any, bool) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, false
	}
	password := u.User.Username()
	host, port, ok := getHostPort(u)
	if !ok || password == "" {
		return nil, false
	}

	q := u.Query()
	server := map[string]any{
		"address":  host,
		"port":     port,
		"password": password,
	}
	if email := u.Fragment; email != "" {
		server["email"] = email
	}

	return map[string]any{
		"tag":            "proxy",
		"protocol":       "trojan",
		"settings":       map[string]any{"servers": []map[string]any{server}},
		"streamSettings": buildStreamSettings(q, u.Fragment),
	}, true
}

func buildSSOutbound(line string) (map[string]any, bool) {
	rest := strings.TrimPrefix(line, "ss://")
	mainPart := strings.SplitN(rest, "#", 2)[0]
	mainPart = strings.SplitN(mainPart, "?", 2)[0]
	if mainPart == "" {
		return nil, false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(mainPart)
	if err == nil && strings.Contains(string(decoded), "@") {
		mainPart = string(decoded)
	}

	var userInfo, serverPart string
	if strings.Contains(mainPart, "@") {
		parts := strings.SplitN(mainPart, "@", 2)
		userInfo = parts[0]
		serverPart = parts[1]
	} else {
		return nil, false
	}

	if v, err := base64.StdEncoding.DecodeString(userInfo); err == nil {
		userInfo = string(v)
	} else if v, err := base64.RawStdEncoding.DecodeString(userInfo); err == nil {
		userInfo = string(v)
	}

	mp := strings.SplitN(userInfo, ":", 2)
	if len(mp) != 2 {
		return nil, false
	}

	host, port, err := splitHostPort(serverPart)
	if err != nil {
		return nil, false
	}

	return map[string]any{
		"tag":      "proxy",
		"protocol": "shadowsocks",
		"settings": map[string]any{
			"servers": []map[string]any{
				{
					"address":  host,
					"port":     port,
					"method":   mp[0],
					"password": mp[1],
				},
			},
		},
	}, true
}

func buildVMessOutbound(line string) (map[string]any, bool) {
	raw := strings.TrimPrefix(line, "vmess://")
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(raw)
		if err != nil {
			return nil, false
		}
	}

	var c map[string]any
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, false
	}

	host := getAnyString(c["add"])
	portText := getAnyString(c["port"])
	id := getAnyString(c["id"])
	if host == "" || portText == "" || id == "" {
		return nil, false
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, false
	}

	q := url.Values{}
	q.Set("type", pickFirst(getAnyString(c["net"]), "tcp"))
	q.Set("security", pickFirst(getAnyString(c["tls"]), "none"))
	q.Set("path", getAnyString(c["path"]))
	q.Set("host", getAnyString(c["host"]))
	q.Set("sni", getAnyString(c["sni"]))
	q.Set("alpn", getAnyString(c["alpn"]))
	q.Set("fp", getAnyString(c["fp"]))

	user := map[string]any{
		"id":       id,
		"alterId":  mustAtoi(getAnyString(c["aid"])),
		"security": pickFirst(getAnyString(c["scy"]), "auto"),
	}
	return map[string]any{
		"tag":      "proxy",
		"protocol": "vmess",
		"settings": map[string]any{
			"vnext": []map[string]any{
				{
					"address": host,
					"port":    port,
					"users":   []map[string]any{user},
				},
			},
		},
		"streamSettings": buildStreamSettings(q, getAnyString(c["ps"])),
	}, true
}

func buildStreamSettings(q url.Values, fallbackHost string) map[string]any {
	network := pickFirst(q.Get("type"), "tcp")
	security := normalizeSecurity(q.Get("security"))
	s := map[string]any{
		"network":  network,
		"security": security,
	}

	hostHeader := pickFirst(q.Get("host"), fallbackHost)
	switch network {
	case "ws":
		ws := map[string]any{
			"path": pickFirst(q.Get("path"), "/"),
		}
		if hostHeader != "" {
			ws["headers"] = map[string]any{"Host": hostHeader}
		}
		s["wsSettings"] = ws
	case "grpc":
		g := map[string]any{}
		if name := q.Get("serviceName"); name != "" {
			g["serviceName"] = name
		}
		if mode := q.Get("mode"); mode != "" {
			g["multiMode"] = mode == "multi"
		}
		s["grpcSettings"] = g
	case "tcp":
		if headerType := q.Get("headerType"); headerType == "http" {
			tcp := map[string]any{
				"header": map[string]any{
					"type": "http",
				},
			}
			s["tcpSettings"] = tcp
		}
	}

	switch security {
	case "tls":
		tls := map[string]any{}
		if name := pickFirst(q.Get("sni"), hostHeader); name != "" {
			tls["serverName"] = name
		}
		if alpn := q.Get("alpn"); alpn != "" {
			tls["alpn"] = strings.Split(alpn, ",")
		}
		if fp := q.Get("fp"); fp != "" {
			tls["fingerprint"] = fp
		}
		if insecure := q.Get("insecure"); insecure == "1" || strings.EqualFold(insecure, "true") {
			tls["allowInsecure"] = true
		}
		s["tlsSettings"] = tls
	case "reality":
		reality := map[string]any{}
		if name := pickFirst(q.Get("sni"), hostHeader); name != "" {
			reality["serverName"] = name
		}
		if pk := q.Get("pbk"); pk != "" {
			reality["publicKey"] = pk
		}
		if sid := q.Get("sid"); sid != "" {
			reality["shortId"] = sid
		}
		if spx := q.Get("spx"); spx != "" {
			reality["spiderX"] = spx
		}
		if fp := q.Get("fp"); fp != "" {
			reality["fingerprint"] = fp
		}
		s["realitySettings"] = reality
	}

	return s
}

func normalizeSecurity(sec string) string {
	sec = strings.ToLower(strings.TrimSpace(sec))
	if sec == "" || sec == "none" {
		return "none"
	}
	if sec == "tls" || sec == "reality" {
		return sec
	}
	return "none"
}

func buildXrayConfig(outbound map[string]any, httpPort int) map[string]any {
	return map[string]any{
		"log": map[string]any{
			"loglevel": "warning",
		},
		"inbounds": []map[string]any{
			{
				"listen":   "127.0.0.1",
				"port":     httpPort,
				"protocol": "http",
				"settings": map[string]any{},
			},
		},
		"outbounds": []map[string]any{
			outbound,
		},
	}
}

func freeTCPPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func getHostPort(u *url.URL) (string, int, bool) {
	host := u.Hostname()
	p := u.Port()
	if host == "" || p == "" {
		return "", 0, false
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, false
	}
	return host, port, true
}

func splitHostPort(s string) (string, int, error) {
	u := "dummy://" + s
	parsed, err := url.Parse(u)
	if err != nil {
		return "", 0, err
	}
	host := parsed.Hostname()
	p := parsed.Port()
	port, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func getAnyString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.Itoa(int(t))
	default:
		return ""
	}
}

func pickFirst(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func exitWithError(err error) {
	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}
