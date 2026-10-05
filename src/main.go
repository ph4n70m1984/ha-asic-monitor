package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/256foundation/asic-rs/go/asic_go"
)

type Output struct {
	IP          string   `json:"ip"`
	Model       string   `json:"model"`
	Make        string   `json:"make"`
	Firmware    string   `json:"firmware"`
	APIVersion  string   `json:"api_version,omitempty"`
	IsMining    bool     `json:"is_mining"`
	HashrateTH  float64  `json:"hashrate_th"`
	Wattage     *float64 `json:"wattage,omitempty"`
	MaxChipTemp *float64 `json:"max_chip_temp,omitempty"`
	PoolURL     string   `json:"pool_url,omitempty"`
	PoolUser    string   `json:"pool_user,omitempty"`
	CanRestart  bool     `json:"can_restart"`
}

type TokenResp struct {
	STATUS string `json:"STATUS"`
	Msg    string `json:"Msg"`
	Code   int    `json:"Code"`
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// executeWhatsminerTCP отправляет JSON-RPC команду на TCP сокет
func executeWhatsminerTCP(ip string, port int, reqBytes []byte) ([]byte, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	reader := bufio.NewReader(conn)

	if !strings.HasSuffix(string(reqBytes), "\n") {
		reqBytes = append(reqBytes, '\n')
	}

	if _, err := conn.Write(reqBytes); err != nil {
		return nil, err
	}

	resp, err := reader.ReadBytes('\x00')
	if err != nil {
		resp, err = reader.ReadBytes('\n')
	}
	return resp, err
}

// executeWhatsminerHTTP отправляет JSON команду на HTTP API веб-сервера майнера
func executeWhatsminerHTTP(ip, endpoint string, reqBytes []byte, user, password string) ([]byte, error) {
	url := fmt.Sprintf("http://%s%s", ip, endpoint)
	client := &http.Client{Timeout: 4 * time.Second}

	req, err := http.NewRequest("POST", url, strings.NewReader(string(reqBytes)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if user != "" && password != "" {
		req.SetBasicAuth(user, password)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func extractSalt(res map[string]interface{}) string {
	if msg, ok := res["msg"].(map[string]interface{}); ok {
		if s, ok := msg["salt"].(string); ok && s != "" {
			return s
		}
	}
	if s, ok := res["salt"].(string); ok && s != "" {
		return s
	}
	return ""
}

// getSalt пробует получить уникальную соль майнера через HTTP API и TCP сокеты
func getSalt(ip, user, password string) (string, string, error) {
	req := `{"cmd":"get.device.info"}`

	// 1. Проверяем современные HTTP API эндпоинты MicroBT
	for _, ep := range []string{"/api/v1", "/cgi-bin/api.cgi", "/api"} {
		resp, err := executeWhatsminerHTTP(ip, ep, []byte(req), user, password)
		if err == nil && len(resp) > 0 {
			var res map[string]interface{}
			if json.Unmarshal(resp, &res) == nil {
				if salt := extractSalt(res); salt != "" {
					return salt, ep, nil
				}
			}
		}
	}

	// 2. Фолбэк на TCP порты (4028, 80, 8080)
	for _, port := range []int{4028, 80, 8080} {
		resp, err := executeWhatsminerTCP(ip, port, []byte(req))
		if err == nil && len(resp) > 0 {
			var res map[string]interface{}
			clean := strings.TrimRight(string(resp), "\x00\r\n")
			if json.Unmarshal([]byte(clean), &res) == nil {
				if salt := extractSalt(res); salt != "" {
					return salt, fmt.Sprintf("tcp:%d", port), nil
				}
			}
		}
	}

	return "", "", fmt.Errorf("salt не получен ни по HTTP, ни по TCP сокетам")
}

// sendWhatsminerServiceCmd выполняет команду set.miner.service ("stop", "start", "restart")
func sendWhatsminerServiceCmd(ip, user, password, action string) error {
	var serviceParam string
	switch action {
	case "power_off", "stop":
		serviceParam = "stop"
	case "resume", "start":
		serviceParam = "start"
	case "restart":
		serviceParam = "restart"
	default:
		serviceParam = action
	}

	fmt.Fprintf(os.Stderr, "[WM-V4] Запрос salt у %s...\n", ip)
	salt, transport, err := getSalt(ip, user, password)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[WM-V4] Получен salt: %s (транспорт: %s)\n", salt, transport)

	account := user
	if account == "" || account == "root" {
		account = "admin"
	}

	cmdName := "set.miner.service"
	ts := time.Now().Unix()

	// 1. Токен: Base64(SHA256(cmd + password + salt + ts))[:8]
	concat := fmt.Sprintf("%s%s%s%d", cmdName, password, salt, ts)
	hash := sha256.Sum256([]byte(concat))
	b64 := base64.StdEncoding.EncodeToString(hash[:])
	token := b64
	if len(b64) > 8 {
		token = b64[:8]
	}

	reqMap := map[string]interface{}{
		"cmd":     cmdName,
		"account": account,
		"ts":      ts,
		"token":   token,
		"param":   serviceParam,
	}

	reqBytes, _ := json.Marshal(reqMap)
	fmt.Fprintf(os.Stderr, "[WM-V4] Отправка запроса: %s\n", string(reqBytes))

	var respBytes []byte
	if strings.HasPrefix(transport, "tcp:") {
		var port int
		fmt.Sscanf(transport, "tcp:%d", &port)
		respBytes, err = executeWhatsminerTCP(ip, port, reqBytes)
	} else {
		respBytes, err = executeWhatsminerHTTP(ip, transport, reqBytes, user, password)
	}

	if err != nil {
		return fmt.Errorf("ошибка передачи данных: %w", err)
	}

	respStr := strings.TrimRight(string(respBytes), "\x00\r\n")
	fmt.Fprintf(os.Stderr, "[WM-V4] Ответ майнера: %s\n", respStr)

	var res map[string]interface{}
	if err := json.Unmarshal([]byte(respStr), &res); err == nil {
		code, _ := res["code"].(float64)
		msg, _ := res["msg"].(string)
		status, _ := res["status"].(string)

		if code == 0 || strings.EqualFold(msg, "ok") || strings.EqualFold(status, "success") {
			fmt.Fprintf(os.Stderr, "[WM-V4] Майнер успешно выполнил команду '%s'!\n", serviceParam)
			return nil
		}
	}

	return fmt.Errorf("майнер отклонил команду: %s", respStr)
}

// sendWhatsminerLegacyCmd выполняет старый get_token протокол для WhatsMiner v1/v2
func sendWhatsminerLegacyCmd(ip, user, password, cmd string) error {
	fmt.Fprintf(os.Stderr, "[WM-Legacy] Запрос token через get_token у %s...\n", ip)
	respBytes, err := executeWhatsminerTCP(ip, 4028, []byte(`{"cmd":"get_token"}`))
	if err != nil {
		return err
	}

	cleanLine := strings.TrimRight(string(respBytes), "\x00\r\n")
	var tResp TokenResp
	if err := json.Unmarshal([]byte(cleanLine), &tResp); err != nil {
		return fmt.Errorf("ошибка парсинга токена: %w", err)
	}

	token := tResp.Msg
	if token == "" || tResp.STATUS != "S" {
		return fmt.Errorf("майнер отклонил get_token: %s", cleanLine)
	}

	candidates := []struct {
		desc string
		sign string
	}{
		{"sha256(password+token)", sha256Hex(password + token)},
		{"sha256(user+password+token)", sha256Hex(user + password + token)},
		{"sha256(admin+password+token)", sha256Hex("admin" + password + token)},
	}

	for _, cand := range candidates {
		req := map[string]interface{}{
			"cmd":   cmd,
			"token": token,
			"sign":  cand.sign,
		}
		reqBytes, _ := json.Marshal(req)
		respLine, err := executeWhatsminerTCP(ip, 4028, reqBytes)
		if err != nil {
			continue
		}

		respStr := strings.TrimRight(string(respLine), "\x00\r\n")
		var res map[string]interface{}
		if err := json.Unmarshal([]byte(respStr), &res); err == nil {
			if status, ok := res["STATUS"].(string); ok && status == "S" {
				fmt.Fprintf(os.Stderr, "[WM-Legacy] Команда '%s' успешно выполнена через %s!\n", cmd, cand.desc)
				return nil
			}
		}
	}
	return fmt.Errorf("legacy попытки авторизации отклонены")
}

// dispatchCommand распределяет выполнение команд управления
func dispatchCommand(ip, user, password, action string, miner *asic_go.Miner) error {
	var apiVer string
	if miner != nil {
		if verPtr, err := miner.GetAPIVersion(); err == nil && verPtr != nil {
			apiVer = *verPtr
			fmt.Fprintf(os.Stderr, "[WM-AUTH] Опознана версия API майнера: %s\n", apiVer)
		}
	}

	// Для версий 3.x, 4.x или по умолчанию — современный солевой протокол set.miner.service
	if apiVer == "" || strings.HasPrefix(apiVer, "3") || strings.HasPrefix(apiVer, "4") || strings.Contains(apiVer, "v3") || strings.Contains(apiVer, "v4") {
		err := sendWhatsminerServiceCmd(ip, user, password, action)
		if err == nil {
			return nil
		}
		fmt.Fprintf(os.Stderr, "[WM-AUTH] Ошибка сервисного протокола (%v), пробуем Legacy сокет...\n", err)
	}

	legacyCmd := "power_off"
	if action == "resume" || action == "restart" {
		legacyCmd = "restart"
	}
	return sendWhatsminerLegacyCmd(ip, user, password, legacyCmd)
}

func main() {
	cmd := flag.String("cmd", "poll", "Action: scan, poll, restart, pause, resume")
	target := flag.String("target", "", "IP for poll/restart/pause/resume, or subnets for scan")
	user := flag.String("user", getEnv("ASIC_USER", "admin"), "Miner RPC username")
	pass := flag.String("pass", getEnv("ASIC_PASS", "admin"), "Miner RPC password")
	flag.Parse()

	switch *cmd {
	case "scan":
		subnets := strings.Split(*target, ",")
		var discovered []string
		for _, s := range subnets {
			trimmed := strings.TrimSpace(s)
			if trimmed == "" {
				continue
			}
			f, err := asic_go.NewMinerFactoryFromSubnet(trimmed)
			if err != nil {
				continue
			}
			f.WithConcurrentLimit(2500)
			miners, err := f.Scan()
			if err == nil {
				for _, m := range miners {
					if ip, err := m.GetIP(); err == nil && ip != "" {
						discovered = append(discovered, ip)
					}
					m.Close()
				}
			}
			f.Close()
		}
		_ = json.NewEncoder(os.Stdout).Encode(discovered)

	case "poll":
		f := asic_go.NewMinerFactory().WithIdentificationTimeoutSecs(8)
		defer f.Close()

		miner, err := f.GetMiner(*target)
		if err != nil {
			os.Exit(1)
		}
		defer miner.Close()

		if *user != "" && *pass != "" {
			_ = miner.SetAuth(*user, *pass)
		}

		data, err := miner.GetData()
		if err != nil {
			os.Exit(2)
		}

		hashrate, _ := data.HashrateTH()
		caps, _ := miner.Supports()

		var apiVerStr string
		if vPtr, err := miner.GetAPIVersion(); err == nil && vPtr != nil {
			apiVerStr = *vPtr
		}

		var maxTemp *float64
		for _, b := range data.Hashboards {
			for _, chip := range b.Chips {
				if chip.Temperature != nil {
					val := *chip.Temperature
					if maxTemp == nil || val > *maxTemp {
						maxTemp = &val
					}
				}
			}
		}

		if maxTemp == nil && data.AverageTemperature != nil {
			val := *data.AverageTemperature
			maxTemp = &val
		}

		var poolURL, poolUser string
		pools, err := miner.GetPools()
		if err == nil && len(pools) > 0 {
			for _, group := range pools {
				for _, p := range group.Pools {
					if p.URL != nil {
						poolURL = p.URL.String()
						if p.User != nil {
							poolUser = *p.User
						}
						break
					}
				}
				if poolURL != "" {
					break
				}
			}
		}

		out := Output{
			IP:          *target,
			Model:       data.DeviceInfo.Model,
			Make:        data.DeviceInfo.Make,
			Firmware:    data.DeviceInfo.Firmware,
			APIVersion:  apiVerStr,
			IsMining:    data.IsMining,
			HashrateTH:  hashrate,
			Wattage:     data.Wattage,
			MaxChipTemp: maxTemp,
			PoolURL:     poolURL,
			PoolUser:    poolUser,
			CanRestart:  caps.Restart,
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)

	case "pause":
		f := asic_go.NewMinerFactory().WithIdentificationTimeoutSecs(5)
		miner, err := f.GetMiner(*target)
		f.Close()

		handled := false
		if err == nil {
			if *user != "" && *pass != "" {
				_ = miner.SetAuth(*user, *pass)
			}
			ok, _ := miner.Pause(nil)
			handled = ok
		}

		if !handled {
			if err := dispatchCommand(*target, *user, *pass, "stop", miner); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
		}
		if miner != nil {
			miner.Close()
		}

	case "resume":
		f := asic_go.NewMinerFactory().WithIdentificationTimeoutSecs(5)
		miner, err := f.GetMiner(*target)
		f.Close()

		handled := false
		if err == nil {
			if *user != "" && *pass != "" {
				_ = miner.SetAuth(*user, *pass)
			}
			ok, _ := miner.Resume(nil)
			handled = ok
		}

		if !handled {
			if err := dispatchCommand(*target, *user, *pass, "start", miner); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
		}
		if miner != nil {
			miner.Close()
		}

	case "restart":
		f := asic_go.NewMinerFactory().WithIdentificationTimeoutSecs(5)
		miner, err := f.GetMiner(*target)
		f.Close()

		handled := false
		if err == nil {
			if *user != "" && *pass != "" {
				_ = miner.SetAuth(*user, *pass)
			}
			ok, _ := miner.Restart()
			handled = ok
		}

		if !handled {
			if err := dispatchCommand(*target, *user, *pass, "restart", miner); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
		}
		if miner != nil {
			miner.Close()
		}
	}
}
