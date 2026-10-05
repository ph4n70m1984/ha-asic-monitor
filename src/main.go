package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
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

type TokenResp struct {
	STATUS string `json:"STATUS"`
	Msg    string `json:"Msg"`
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

// sendPrivilegedWhatsminerCmd выполняет авторизацию через get_token и отправляет привилегированную команду
func sendPrivilegedWhatsminerCmd(ip, user, password, cmd string) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "4028"), 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect error: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	// Шаг 1: Запрашиваем токен
	if _, err := conn.Write([]byte(`{"cmd":"get_token"}` + "\n")); err != nil {
		return fmt.Errorf("failed to request token: %w", err)
	}

	line, err := reader.ReadBytes('\x00')
	if err != nil {
		// Некоторые версии WhatsMiner завершают ответ переходом строки \n, а не null-byte
		line, err = reader.ReadBytes('\n')
		if err != nil {
			return fmt.Errorf("failed to read token response: %w", err)
		}
	}

	var tResp TokenResp
	cleanLine := strings.TrimRight(string(line), "\x00\r\n")
	if err := json.Unmarshal([]byte(cleanLine), &tResp); err != nil {
		return fmt.Errorf("failed to parse token response: %w", err)
	}

	token := tResp.Msg
	if token == "" {
		return fmt.Errorf("empty token received from miner")
	}

	// Шаг 2: Расчет SHA-256 подписи
	// WhatsMiner протокол: sha256(password + token)
	h := sha256.New()
	h.Write([]byte(password + token))
	sign := hex.EncodeToString(h.Sum(nil))

	// Шаг 3: Отправка привилегированной команды
	req := map[string]string{
		"cmd":   cmd,
		"token": token,
		"sign":  sign,
	}
	reqBytes, _ := json.Marshal(req)
	reqBytes = append(reqBytes, '\n')

	if _, err := conn.Write(reqBytes); err != nil {
		return fmt.Errorf("failed to send privileged command: %w", err)
	}

	// Читаем подтверждение выполнения
	respLine, _ := reader.ReadBytes('\n')
	if len(respLine) > 0 {
		var res map[string]interface{}
		_ = json.Unmarshal(respLine, &res)
		// Если статус F (Failed), пробуем альтернативную схему sha256(user + password + token)
		if status, ok := res["STATUS"].(string); ok && status == "F" {
			h2 := sha256.New()
			h2.Write([]byte(user + password + token))
			req["sign"] = hex.EncodeToString(h2.Sum(nil))
			reqBytes2, _ := json.Marshal(req)
			reqBytes2 = append(reqBytes2, '\n')
			_, _ = conn.Write(reqBytes2)
		}
	}

	return nil
}

func main() {
	cmd := flag.String("cmd", "poll", "Action: scan, poll, restart, pause, resume")
	target := flag.String("target", "", "IP for poll/restart/pause/resume, or subnets for scan")
	user := flag.String("user", getEnv("ASIC_USER", "root"), "Miner RPC username")
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
		f := asic_go.NewMinerFactory().WithIdentificationTimeoutSecs(8)
		defer f.Close()

		miner, err := f.GetMiner(*target)
		if err == nil {
			if *user != "" && *pass != "" {
				_ = miner.SetAuth(*user, *pass)
			}
			_, _ = miner.Restart()
			miner.Close()
		} else {
			_ = sendPrivilegedWhatsminerCmd(*target, *user, *pass, "restart")
		}

	case "pause":
		// Приостановка майнинга (выключение плат хэширования)
		f := asic_go.NewMinerFactory().WithIdentificationTimeoutSecs(8)
		defer f.Close()

		miner, err := f.GetMiner(*target)
		handled := false
		if err == nil {
			if *user != "" && *pass != "" {
				_ = miner.SetAuth(*user, *pass)
			}
			ok, _ := miner.Pause(nil)
			handled = ok
			miner.Close()
		}

		// Если FFI-метод не отработал (сток WhatsMiner), вызываем привилегированный power_off
		if !handled {
			_ = sendPrivilegedWhatsminerCmd(*target, *user, *pass, "power_off")
		}

	case "resume":
		// Возобновление майнинга
		f := asic_go.NewMinerFactory().WithIdentificationTimeoutSecs(8)
		defer f.Close()

		miner, err := f.GetMiner(*target)
		handled := false
		if err == nil {
			if *user != "" && *pass != "" {
				_ = miner.SetAuth(*user, *pass)
			}
			ok, _ := miner.Resume(nil)
			handled = ok
			miner.Close()
		}

		// Для стока WhatsMiner возврат в работу делается через рестарт btminer сервиса
		if !handled {
			_ = sendPrivilegedWhatsminerCmd(*target, *user, *pass, "restart")
		}
	}
}
