package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
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
	IsMining    bool     `json:"is_mining"`
	HashrateTH  float64  `json:"hashrate_th"`
	Wattage     *float64 `json:"wattage,omitempty"`
	MaxChipTemp *float64 `json:"max_chip_temp,omitempty"`
	PoolURL     string   `json:"pool_url,omitempty"`
	PoolUser    string   `json:"pool_user,omitempty"`
	CanRestart  bool     `json:"can_restart"`
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

// executeWhatsminerTCP отправляет JSON команду на сокет 4028 и возвращает сырой ответ
func executeWhatsminerTCP(ip string, reqBytes []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "4028"), 4*time.Second)
	if err != nil {
		return nil, fmt.Errorf("соединение с %s:4028: %w", ip, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	if !strings.HasSuffix(string(reqBytes), "\n") {
		reqBytes = append(reqBytes, '\n')
	}

	if _, err := conn.Write(reqBytes); err != nil {
		return nil, fmt.Errorf("ошибка отправки данных: %w", err)
	}

	resp, err := reader.ReadBytes('\x00')
	if err != nil {
		resp, err = reader.ReadBytes('\n')
	}
	return resp, err
}

// getSalt запрашивает salt через get.device.info
func getSalt(ip string) (string, error) {
	req := `{"cmd":"get.device.info"}`
	respBytes, err := executeWhatsminerTCP(ip, []byte(req))
	if err != nil {
		return "", err
	}

	cleanResp := strings.TrimRight(string(respBytes), "\x00\r\n")
	var res map[string]interface{}
	if err := json.Unmarshal([]byte(cleanResp), &res); err != nil {
		return "", fmt.Errorf("ошибка парсинга get.device.info: %w (ответ: %s)", err, cleanResp)
	}

	// Поиск salt в структуре ответа
	if msg, ok := res["msg"].(map[string]interface{}); ok {
		if s, ok := msg["salt"].(string); ok && s != "" {
			return s, nil
		}
	}
	if s, ok := res["salt"].(string); ok && s != "" {
		return s, nil
	}

	return "", fmt.Errorf("в ответе get.device.info нет поля salt: %s", cleanResp)
}

// generateToken вычисляет токен по спецификации MicroBT:
// Base64(SHA256(cmd + password + salt + timestamp))[:8]
func generateToken(cmd, password, salt string, ts int64) string {
	payload := fmt.Sprintf("%s%s%s%d", cmd, password, salt, ts)
	hash := sha256.Sum256([]byte(payload))
	b64 := base64.StdEncoding.EncodeToString(hash[:])
	if len(b64) >= 8 {
		return b64[:8]
	}
	return b64
}

// sendWhatsminerModernCmd отправляет привилегированные команды с токеном
func sendWhatsminerModernCmd(ip, user, password, action string) error {
	fmt.Fprintf(os.Stderr, "[WM-V4] Запрос salt у %s...\n", ip)
	salt, err := getSalt(ip)
	if err != nil {
		return fmt.Errorf("не удалось получить salt: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[WM-V4] Получен salt: %s\n", salt)

	var targetCmds []struct {
		cmd   string
		param interface{}
	}

	if action == "power_off" {
		targetCmds = []struct {
			cmd   string
			param interface{}
		}{
			{"set.miner.power", "off"},
			{"set.power_off", nil},
			{"set.miner.power_off", nil},
		}
	} else if action == "resume" {
		targetCmds = []struct {
			cmd   string
			param interface{}
		}{
			{"set.miner.power", "on"},
			{"set.miner.power_on", nil},
			{"set.miner.restart", nil},
		}
	} else { // restart
		targetCmds = []struct {
			cmd   string
			param interface{}
		}{
			{"set.miner.restart", nil},
			{"set.system.reboot", nil},
		}
	}

	account := user
	if account == "" || account == "root" {
		account = "admin"
	}

	for _, tc := range targetCmds {
		ts := time.Now().Unix()
		token := generateToken(tc.cmd, password, salt, ts)

		reqMap := map[string]interface{}{
			"cmd":     tc.cmd,
			"account": account,
			"ts":      ts,
			"token":   token,
		}
		if tc.param != nil {
			reqMap["param"] = tc.param
		}

		reqBytes, _ := json.Marshal(reqMap)
		fmt.Fprintf(os.Stderr, "[WM-V4] Отправка команды: %s\n", string(reqBytes))

		respBytes, err := executeWhatsminerTCP(ip, reqBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WM-V4] Ошибка сети: %v\n", err)
			continue
		}

		respStr := strings.TrimRight(string(respBytes), "\x00\r\n")
		fmt.Fprintf(os.Stderr, "[WM-V4] Ответ майнера: %s\n", respStr)

		var res map[string]interface{}
		if err := json.Unmarshal([]byte(respStr), &res); err == nil {
			status, _ := res["status"].(string)
			code, _ := res["code"].(float64)
			msg, _ := res["msg"].(string)
			if strings.EqualFold(status, "success") || strings.EqualFold(status, "s") || code == 0 || strings.Contains(strings.ToLower(msg), "success") {
				fmt.Fprintf(os.Stderr, "[WM-V4] Команда '%s' успешно выполнена!\n", tc.cmd)
				return nil
			}
		}
	}

	return fmt.Errorf("майнер не подтвердил выполнение команды %s", action)
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
			IsMining:    data.IsMining,
			HashrateTH:  hashrate,
			Wattage:     data.Wattage,
			MaxChipTemp: maxTemp,
			PoolURL:     poolURL,
			PoolUser:    poolUser,
			CanRestart:  caps.Restart,
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)

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
			miner.Close()
		}

		if !handled {
			if err := sendWhatsminerModernCmd(*target, *user, *pass, "restart"); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
		}

	case "pause":
		// Сначала проверяем FFI
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
			miner.Close()
		}

		// Для стока WhatsMiner переходим на солевой API MicroBT
		if !handled {
			if err := sendWhatsminerModernCmd(*target, *user, *pass, "power_off"); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
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
			miner.Close()
		}

		if !handled {
			if err := sendWhatsminerModernCmd(*target, *user, *pass, "resume"); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
		}
	}
}
