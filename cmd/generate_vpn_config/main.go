package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func first(values map[string][]string, key, def string) string {
	v, ok := values[key]
	if !ok || len(v) == 0 {
		return def
	}
	return v[0]
}

func parseVLESSURI(raw string, index int) (map[string]any, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("строка #%d: ошибка парсинга URI", index)
	}
	if parsed.Scheme != "vless" {
		return nil, fmt.Errorf("строка #%d не является vless-ссылкой", index)
	}

	if parsed.Hostname() == "" || parsed.Port() == "" || parsed.User == nil || parsed.User.Username() == "" {
		return nil, fmt.Errorf("строка #%d: отсутствуют host/port/uuid", index)
	}

	query := parsed.Query()
	netType := first(query, "type", "tcp")
	security := first(query, "security", "")
	flow := first(query, "flow", "")
	fingerprint := first(query, "fp", "chrome")

	user := map[string]any{
		"id":         parsed.User.Username(),
		"encryption": first(query, "encryption", "none"),
		"flow":       flow,
	}

	streamSettings := map[string]any{
		"network": netType,
	}
	if security != "" {
		streamSettings["security"] = security
	}

	if security == "reality" {
		streamSettings["realitySettings"] = map[string]any{
			"show":        false,
			"fingerprint": fingerprint,
			"serverName":  first(query, "sni", ""),
			"publicKey":   first(query, "pbk", ""),
			"shortId":     first(query, "sid", ""),
			"spiderX":     first(query, "spx", "/"),
		}
	} else if security == "tls" {
		alpnRaw := first(query, "alpn", "")
		alpn := make([]string, 0)
		if alpnRaw != "" {
			for _, item := range strings.Split(alpnRaw, ",") {
				item = strings.TrimSpace(item)
				if item != "" {
					alpn = append(alpn, item)
				}
			}
		}

		tlsSettings := map[string]any{
			"show":          false,
			"fingerprint":   fingerprint,
			"serverName":    first(query, "sni", ""),
			"allowInsecure": strings.EqualFold(first(query, "allowInsecure", "false"), "true"),
		}
		if len(alpn) > 0 {
			tlsSettings["alpn"] = alpn
		}
		streamSettings["tlsSettings"] = tlsSettings
	}

	if netType == "grpc" {
		streamSettings["grpcSettings"] = map[string]any{
			"serviceName": first(query, "serviceName", ""),
			"multiMode":   strings.EqualFold(first(query, "mode", ""), "multi"),
		}
	} else if netType == "xhttp" {
		streamSettings["xhttpSettings"] = map[string]any{
			"path": first(query, "path", first(query, "spx", "/")),
			"host": first(query, "host", ""),
			"mode": first(query, "mode", "auto"),
		}
	} else if netType == "tcp" {
		streamSettings["tcpSettings"] = map[string]any{}
	}

	tag := fmt.Sprintf("node-%03d", index)
	if parsed.Fragment != "" {
		if decoded, decErr := url.QueryUnescape(parsed.Fragment); decErr == nil {
			tag = fmt.Sprintf("%s %s", tag, decoded)
		} else {
			tag = fmt.Sprintf("%s %s", tag, parsed.Fragment)
		}
	}

	port, convErr := strconv.Atoi(parsed.Port())
	if convErr != nil {
		return nil, fmt.Errorf("строка #%d: некорректный порт", index)
	}

	return map[string]any{
		"protocol": "vless",
		"tag":      tag,
		"settings": map[string]any{
			"vnext": []any{
				map[string]any{
					"address": parsed.Hostname(),
					"port":    port,
					"users":   []any{user},
				},
			},
		},
		"streamSettings": streamSettings,
	}, nil
}

func buildConfig(outbounds []map[string]any, preferredTag string) map[string]any {

	outboundItems := make([]any, 0, len(outbounds)+2)
	for _, ob := range outbounds {
		outboundItems = append(outboundItems, ob)
	}
	outboundItems = append(outboundItems,
		map[string]any{"protocol": "freedom", "tag": "direct"},
		map[string]any{"protocol": "blackhole", "tag": "block"},
	)

	return map[string]any{
		"remarks": "Auto generated from live_50.txt",
		"dns": map[string]any{
			"queryStrategy": "UseIP",
			"servers":       []string{"1.1.1.1", "1.0.0.1"},
		},
		"inbounds": []any{
			map[string]any{
				"tag":      "socks",
				"listen":   "127.0.0.1",
				"port":     10808,
				"protocol": "socks",
				"settings": map[string]any{
					"auth": "noauth",
					"udp":  true,
				},
				"sniffing": map[string]any{
					"enabled":      true,
					"destOverride": []string{"http", "tls", "quic"},
					"routeOnly":    false,
				},
			},
			map[string]any{
				"tag":      "http",
				"listen":   "127.0.0.1",
				"port":     10809,
				"protocol": "http",
				"settings": map[string]any{
					"allowTransparent": false,
				},
				"sniffing": map[string]any{
					"enabled":      true,
					"destOverride": []string{"http", "tls", "quic"},
					"routeOnly":    false,
				},
			},
		},
		"outbounds": outboundItems,
		"routing": map[string]any{
			"domainStrategy": "IPIfNonMatch",
			"rules": []any{
				map[string]any{
					"type":        "field",
					"ip":          []string{"geoip:private"},
					"outboundTag": "direct",
				},
				map[string]any{
					"type":        "field",
					"protocol":    []string{"bittorrent"},
					"outboundTag": "block",
				},
				map[string]any{
					"type":        "field",
					"network":     "tcp,udp",
					"outboundTag": preferredTag,
				},
			},
		},
	}
}

type stickyState struct {
	PreferredTag string `json:"preferredTag"`
	StickyUntil  string `json:"stickyUntil"`
}

func firstOutboundTag(outbounds []map[string]any) string {
	if len(outbounds) == 0 {
		return ""
	}
	tag, _ := outbounds[0]["tag"].(string)
	return tag
}

func containsTag(outbounds []map[string]any, tag string) bool {
	for _, ob := range outbounds {
		if t, ok := ob["tag"].(string); ok && t == tag {
			return true
		}
	}
	return false
}

func readStickyState(path string) (stickyState, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return stickyState{}, false
	}
	var st stickyState
	if err := json.Unmarshal(data, &st); err != nil {
		return stickyState{}, false
	}
	if st.PreferredTag == "" || st.StickyUntil == "" {
		return stickyState{}, false
	}
	return st, true
}

func writeStickyState(path string, st stickyState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func choosePreferredTag(outbounds []map[string]any, statePath string, stickyFor time.Duration, now time.Time) (string, string) {
	defaultTag := firstOutboundTag(outbounds)
	if defaultTag == "" {
		return "", "нет доступных узлов"
	}

	st, ok := readStickyState(statePath)
	if ok && containsTag(outbounds, st.PreferredTag) {
		until, err := time.Parse(time.RFC3339, st.StickyUntil)
		if err == nil && now.Before(until) {
			return st.PreferredTag, fmt.Sprintf("использован залипший узел до %s", until.Format(time.RFC3339))
		}
	}

	newState := stickyState{
		PreferredTag: defaultTag,
		StickyUntil:  now.Add(stickyFor).Format(time.RFC3339),
	}
	if err := writeStickyState(statePath, newState); err != nil {
		return defaultTag, fmt.Sprintf("выбран новый узел, но состояние не сохранено: %v", err)
	}
	return defaultTag, fmt.Sprintf("выбран новый узел и зафиксирован до %s", newState.StickyUntil)
}

func readLinks(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	lines := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return nil, scanErr
	}
	return lines, nil
}

func main() {
	input := flag.String("input", "live_50.txt", "Путь до файла со ссылками")
	output := flag.String("output", "generated_config.json", "Путь для результата JSON")
	stickyStatePath := flag.String("sticky-state", "sticky_state.json", "Путь до файла состояния для залипания узла")
	stickyFor := flag.Duration("sticky-for", 30*time.Minute, "На сколько фиксировать выбранный узел")
	flag.Parse()

	links, err := readLinks(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка чтения файла: %v\n", err)
		os.Exit(1)
	}
	if len(links) == 0 {
		fmt.Fprintf(os.Stderr, "Файл пустой или не содержит ссылок: %s\n", *input)
		os.Exit(1)
	}

	outbounds := make([]map[string]any, 0, len(links))
	skipped := 0
	for i, uri := range links {
		outbound, parseErr := parseVLESSURI(uri, i+1)
		if parseErr != nil {
			skipped++
			continue
		}
		outbounds = append(outbounds, outbound)
	}

	if len(outbounds) == 0 {
		fmt.Fprintln(os.Stderr, "Не удалось разобрать ни одной vless-ссылки")
		os.Exit(1)
	}

	preferredTag, stickyMsg := choosePreferredTag(outbounds, *stickyStatePath, *stickyFor, time.Now())
	config := buildConfig(outbounds, preferredTag)
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка сериализации JSON: %v\n", err)
		os.Exit(1)
	}

	if err = os.WriteFile(*output, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка записи файла: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Сгенерирован файл: %s\n", *output)
	fmt.Printf("Разобрано узлов: %d\n", len(outbounds))
	fmt.Printf("Выбранный узел: %s\n", preferredTag)
	fmt.Printf("Sticky: %s\n", stickyMsg)
	if skipped > 0 {
		fmt.Printf("Пропущено строк: %d\n", skipped)
	}
}
