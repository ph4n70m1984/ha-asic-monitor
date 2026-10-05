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

// sendPrivilegedWhatsminerCmd выполняет авторизацию через get_token и отправляет привилегированную команду
func sendPrivilegedWhatsminerCmd(ip, user, password, cmd string) error {
	addr := net.JoinHostPort(ip, "4028")
	conn, err := net.DialTimeout("tcp", addr, 4*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WM-RPC] Connect error to %s: %v\n", addr, err)
		return err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	// Шаг 1: Запрашиваем токен
	if _, err := conn.Write([]byte(`{"cmd":"get_token"}` + "\n")); err != nil {
		fmt.Fprintf(os.Stderr, "[WM-RPC] Failed to request token: %v\n", err)
		return err
	}

	line, err := reader.ReadBytes('\x00')
	if err != nil {
		line, err = reader.ReadBytes('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WM-RPC] Failed to read token: %v\n", err)
			return err
		}
	}

	cleanLine := strings.TrimRight(string(line), "\x00\r\n")
	var tResp TokenResp
	if err := json.Unmarshal([]byte(cleanLine), &tResp); err != nil {
		fmt.Fprintf(os.Stderr, "[WM-RPC] Token parse error: %v (raw: %s)\n", err, cleanLine)
		return err
	}

	token := tResp.Msg
	if token == "" || tResp.STATUS != "S" {
		fmt.Fprintf(os.Stderr, "[WM-RPC] Invalid token response: %s\n", cleanLine)
		return fmt.Errorf("token rejected: %s", cleanLine)
	}

	fmt.Fprintf(os.Stderr, "[WM-RPC] Received token: %s\n", token)

	// Варианты подписей, встречающиеся в прошивках WhatsMiner:
	// 1) sha256(password + token)
	// 2) sha256(admin + password + token)
	// 3) sha256(admin + ":" + password + ":" + token)
	candidates := []struct {
		desc string
		sign string
	}{
		{"sha256(password+token)", sha256Hex(password + token)},
		{"sha256(user+password+token)", sha256Hex(user + password + token)},
		{"sha256(admin+password+token)", sha256Hex("admin" + password + token)},
		{"sha256(admin:password:token)", sha256Hex("admin:" + password + ":" + token)},
	}

	for _, cand := range candidates {
		// Формируем запрос
		req := map[string]interface{}{
			"cmd":   cmd,
			"token": token,
			"sign":  cand.sign,
		}
		reqBytes, _ := json.Marshal(req)
		reqBytes = append(reqBytes, '\n')

		if _, err := conn.Write(reqBytes); err != nil {
			fmt.Fprintf(os.Stderr, "[WM-RPC] Write error: %v\n", err)
			return err
		}

		respLine, err := reader.ReadBytes('\n')
		if err != nil && len(respLine) == 0 {
			respLine, err = reader.ReadBytes('\x00')
		}

		respStr := strings.TrimRight(string(respLine), "\x00\r\n")
		fmt.Fprintf(os.Stderr, "[WM-RPC] Try %s -> Response: %s\n", cand.desc, respStr)

		var res map[string]interface{}
		if err := json.Unmarshal([]byte(respStr), &res); err == nil {
			if status, ok := res["STATUS"].(string); ok && status == "S" {
				fmt.Fprintf(os.Stderr, "[WM-RPC] Command '%s' SUCCESS!\n", cmd)
				return nil
			}
		}
	}

	return fmt.Errorf("all auth attempts rejected by %s", ip)
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
		// Пробуем через FFI asic-rs
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

		// Если FFI Pause вернул false (WhatsMiner Stock), вызываем команду power_off
		if !handled {
			_ = sendPrivilegedWhatsminerCmd(*target, *user, *pass, "power_off")
		}

	case "resume":
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

		// Для возобновления на стоке WhatsMiner используется команда restart майнинг-демона
		if !handled {
			_ = sendPrivilegedWhatsminerCmd(*target, *user, *pass, "restart")
		}
	}
}
