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

func buildConfig(outbounds []map[string]any) map[string]any {
	routeNodeTags := make([]string, 0, len(outbounds))
	for _, item := range outbounds {
		if tag, ok := item["tag"].(string); ok {
			routeNodeTags = append(routeNodeTags, tag)
		}
	}

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
		"burstObservatory": map[string]any{
			"subjectSelector": []string{"node-"},
			"pingConfig": map[string]any{
				"destination":  "http://www.gstatic.com/generate_204",
				"interval":     "15s",
				"sampling":     1,
				"timeout":      "3s",
				"connectivity": "",
			},
		},
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
					"balancerTag": "AUTO_BALANCER",
				},
			},
			"balancers": []any{
				map[string]any{
					"tag":      "AUTO_BALANCER",
					"selector": routeNodeTags,
					"strategy": map[string]any{
						"type": "leastPing",
					},
				},
			},
		},
	}
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

	config := buildConfig(outbounds)
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
	if skipped > 0 {
		fmt.Printf("Пропущено строк: %d\n", skipped)
	}
}
