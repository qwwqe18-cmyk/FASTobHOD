#!/usr/bin/env bash
set -euo pipefail

echo "Шаг 1/2: сбор живых конфигов..."
go run main.go -limit 50 -out live_50.txt -workers 15 -max-latency 2s

echo "Шаг 2/2: генерация итогового JSON..."
go run "cmd/generate_vpn_config/main.go" --input "live_50.txt" --output "generated_config.json"

echo "Готово: generated_config.json обновлен."
