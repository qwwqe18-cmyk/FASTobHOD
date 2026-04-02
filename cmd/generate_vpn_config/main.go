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

// --- Парсинг VLESS ---

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
		return nil, fmt.Errorf("ошибка парсинга URI #%d", index)
	}
	if parsed.Scheme != "vless" {
		return nil, fmt.Errorf("строка #%d не vless", index)
	}

	query := parsed.Query()
	netType := first(query, "type", "tcp")
	security := first(query, "security", "")
	
	user := map[string]any{
		"id":         parsed.User.Username(),
		"encryption": first(query, "encryption", "none"),
		"flow":       first(query, "flow", ""),
	}

	streamSettings := map[string]any{
		"network": netType,
	}
	if security != "" {
		streamSettings["security"] = security
	}

	// Reality / TLS settings
	if security == "reality" {
		streamSettings["realitySettings"] = map[string]any{
			"fingerprint": first(query, "fp", "chrome"),
			"serverName":  first(query, "sni", ""),
			"publicKey":   first(query, "pbk", ""),
			"shortId":     first(query, "sid", ""),
			"spiderX":     first(query, "spx", "/"),
		}
	} else if security == "tls" {
		streamSettings["tlsSettings"] = map[string]any{
			"serverName":    first(query, "sni", ""),
			"allowInsecure": strings.EqualFold(first(query, "allowInsecure", "false"), "true"),
		}
	}

	// Transport settings
	if netType == "grpc" {
		streamSettings["grpcSettings"] = map[string]any{
			"serviceName": first(query, "serviceName", ""),
		}
	} else if netType == "xhttp" {
		streamSettings["xhttpSettings"] = map[string]any{
			"path": first(query, "path", "/"),
			"mode": first(query, "mode", "auto"),
		}
	}

	tag := fmt.Sprintf("node-%03d", index)
	if parsed.Fragment != "" {
		if decoded, decErr := url.QueryUnescape(parsed.Fragment); decErr == nil {
			tag = fmt.Sprintf("node-%03d %s", index, decoded)
		}
	}

	port, _ := strconv.Atoi(parsed.Port())

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

// --- Генерация "Умного" Конфига ---

func buildSmartConfig(outbounds []map[string]any) map[string]any {
	allOutbounds := make([]any, 0)
	for _, ob := range outbounds {
		allOutbounds = append(allOutbounds, ob)
	}
	allOutbounds = append(allOutbounds,
		map[string]any{"protocol": "freedom", "tag": "direct"},
		map[string]any{"protocol": "blackhole", "tag": "block"},
	)

	return map[string]any{
		"remarks": fmt.Sprintf("⚡⚡ПУК⚡⚡СРЕНЬК⚡⚡ (%d узлов)", len(outbounds)),
		"log": map[string]any{"loglevel": "warning"},
		"observatory": map[string]any{
			"subjectSelector": []string{"node-"},
			// Используем Cloudflare для проверки — он обычно доступен везде
			"probeUrl":        "https://cp.cloudflare.com/generate_204",
			"probeInterval":   "60s", // Проверяем КАЖДЫЕ 10 СЕКУНД (агрессивно для мобилы)
		},
		"dns": map[string]any{
			"servers": []any{
				"1.1.1.1",
				"8.8.8.8",
				"localhost",
			},
			"queryStrategy": "UseIP", // Игнорируем кривые DNS оператора
		},
		"inbounds": []any{
			map[string]any{
				"tag": "socks-in", "port": 10808, "listen": "127.0.0.1", "protocol": "socks",
				"settings": map[string]any{"udp": true},
				"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}},
			},
			map[string]any{
				"tag": "http-in", "port": 10809, "listen": "127.0.0.1", "protocol": "http",
				"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}},
			},
		},
		"outbounds": allOutbounds,
		"routing": map[string]any{
			"domainStrategy": "IPIfNonMatch",
			"balancers": []any{
				map[string]any{
					"tag":      "balancer-auto",
					"selector": []string{"node-"},
					"strategy": map[string]any{
						"type": "leastPing", // На мобиле лучше "random" среди живых, чем "leastPing"
					},
					"fallbackTag": outbounds[0]["tag"], // Если всё упало, пытаемся через первый узел
				},
			},
			"rules": []any{
				map[string]any{"type": "field", "ip": []string{"geoip:private"}, "outboundTag": "direct"},
				map[string]any{"type": "field", "protocol": []string{"bittorrent"}, "outboundTag": "block"},
				map[string]any{"type": "field", "network": "tcp,udp", "balancerTag": "balancer-auto"},
			},
		},
	}
}

func main() {
	input := flag.String("input", "live_50.txt", "Файл со ссылками")
	output := flag.String("output", "config.json", "Итоговый конфиг")
	flag.Parse()

	file, err := os.Open(*input)
	if err != nil {
		fmt.Printf("Ошибка: %v\n", err)
		return
	}
	defer file.Close()

	var outbounds []map[string]any
	scanner := bufio.NewScanner(file)
	idx := 1
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if ob, err := parseVLESSURI(line, idx); err == nil {
			outbounds = append(outbounds, ob)
			idx++
		}
	}

	if len(outbounds) == 0 {
		fmt.Println("Не найдено валидных VLESS ссылок")
		return
	}

	config := buildSmartConfig(outbounds)
	data, _ := json.MarshalIndent(config, "", "  ")
	
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		fmt.Printf("Ошибка записи: %v\n", err)
		return
	}

	fmt.Printf("✅ Успешно! Сгенерирован умный конфиг с балансировщиком.\n")
	fmt.Printf("Nodes: %d | Output: %s\n", len(outbounds), *output)
}
