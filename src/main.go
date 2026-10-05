package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
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
	APIVersion  string   `json:"api_version,omitempty"`
	IsMining    bool     `json:"is_mining"`
	HashrateTH  float64  `json:"hashrate_th"`
	Wattage     *float64 `json:"wattage,omitempty"`
	MaxChipTemp *float64 `json:"max_chip_temp,omitempty"`
	PoolURL     string   `json:"pool_url,omitempty"`
	PoolUser    string   `json:"pool_user,omitempty"`
	CanRestart  bool     `json:"can_restart"`
}

type TokenMsg struct {
	NewSalt string `json:"newsalt"`
	Salt    string `json:"salt"`
}

type TokenResponse struct {
	STATUS string          `json:"STATUS"`
	Msg    json.RawMessage `json:"Msg"`
	Code   int             `json:"Code"`
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

// executeWhatsminerSessionCmd выполняет отправку команды с корректным p_hash токеном
func executeWhatsminerSessionCmd(ip, user, password, action string) error {
	addr := net.JoinHostPort(ip, "4028")
	fmt.Fprintf(os.Stderr, "[WM-EXEC] Подключение к %s (действие: %s)...\n", addr, action)

	pHash := sha256Hex(password)

	// Список команд-кандидатов (сначала set.miner.service, затем прямой power_off / restart)
	type tryCmd struct {
		cmd     string
		param   string
		useB64  bool
		useHash bool
	}

	var candidates []tryCmd
	if action == "stop" || action == "pause" {
		candidates = []tryCmd{
			{cmd: "set.miner.service", param: "stop", useB64: true, useHash: true},
			{cmd: "set.power_off", param: "", useB64: true, useHash: true},
			{cmd: "power_off", param: "", useB64: false, useHash: true},
		}
	} else if action == "start" || action == "resume" {
		candidates = []tryCmd{
			{cmd: "set.miner.service", param: "start", useB64: true, useHash: true},
			{cmd: "restart", param: "", useB64: false, useHash: true},
		}
	} else {
		candidates = []tryCmd{
			{cmd: "set.miner.service", param: "restart", useB64: true, useHash: true},
			{cmd: "restart", param: "", useB64: false, useHash: true},
			{cmd: "reboot", param: "", useB64: false, useHash: true},
		}
	}

	accounts := []string{"admin", "super"}
	if user != "" && user != "root" && user != "admin" && user != "super" {
		accounts = append([]string{user}, accounts...)
	}

	for _, cand := range candidates {
		for _, acc := range accounts {
			conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err != nil {
				continue
			}

			_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
			reader := bufio.NewReader(conn)

			// 1. Запрос токена
			if _, err := conn.Write([]byte("{\"command\":\"get_token\"}\n")); err != nil {
				conn.Close()
				continue
			}

			rawResp, err := reader.ReadBytes('\x00')
			if err != nil && len(rawResp) == 0 {
				rawResp, err = reader.ReadBytes('\n')
			}
			if err != nil || len(rawResp) == 0 {
				conn.Close()
				continue
			}

			respStr := strings.TrimRight(string(rawResp), "\x00\r\n")
			var tokResp TokenResponse
			if err := json.Unmarshal([]byte(respStr), &tokResp); err != nil {
				conn.Close()
				continue
			}

			var activeSalt string
			var msgObj TokenMsg
			if err := json.Unmarshal(tokResp.Msg, &msgObj); err == nil {
				activeSalt = msgObj.NewSalt
				if activeSalt == "" {
					activeSalt = msgObj.Salt
				}
			}
			if activeSalt == "" {
				var plainStr string
				if err := json.Unmarshal(tokResp.Msg, &plainStr); err == nil {
					activeSalt = plainStr
				}
			}
			if activeSalt == "" {
				conn.Close()
				continue
			}

			var payloadBytes []byte
			var desc string

			if cand.useB64 {
				// Токен MicroBT v3/v4: Base64(SHA256(cmd + p_hash + salt + ts))[:8]
				ts := time.Now().Unix()
				concat := fmt.Sprintf("%s%s%s%d", cand.cmd, pHash, activeSalt, ts)
				h := sha256.Sum256([]byte(concat))
				b64Token := base64.StdEncoding.EncodeToString(h[:])
				if len(b64Token) > 8 {
					b64Token = b64Token[:8]
				}

				reqMap := map[string]interface{}{
					"cmd":     cand.cmd,
					"ts":      ts,
					"token":   b64Token,
					"account": acc,
				}
				if cand.param != "" {
					reqMap["param"] = cand.param
				}
				payloadBytes, _ = json.Marshal(reqMap)
				desc = fmt.Sprintf("%s (acc=%s, b64_token)", cand.cmd, acc)
			} else {
				// Классический токен: SHA256(p_hash + salt)
				tokenHex := sha256Hex(pHash + activeSalt)
				reqMap := map[string]interface{}{
					"cmd":   cand.cmd,
					"token": tokenHex,
				}
				payloadBytes, _ = json.Marshal(reqMap)
				desc = fmt.Sprintf("%s (hex_token)", cand.cmd)
			}

			payloadBytes = append(payloadBytes, '\n')
			fmt.Fprintf(os.Stderr, "[WM-EXEC] Отправка payload [%s]: %s", desc, string(payloadBytes))

			if _, err := conn.Write(payloadBytes); err != nil {
				conn.Close()
				continue
			}

			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			resRaw, err := reader.ReadBytes('\x00')
			if err != nil && len(resRaw) == 0 {
				resRaw, err = reader.ReadBytes('\n')
			}
			conn.Close()

			if err != nil && len(resRaw) == 0 {
				fmt.Fprintf(os.Stderr, "[WM-EXEC] Сброс сокета на [%s]\n", desc)
				if !cand.useB64 {
					break // для hex команд смена account не имеет значения
				}
				continue
			}

			cmdRespStr := strings.TrimRight(string(resRaw), "\x00\r\n")
			fmt.Fprintf(os.Stderr, "[WM-EXEC] Ответ майнера: %s\n", cmdRespStr)

			var res map[string]interface{}
			if err := json.Unmarshal([]byte(cmdRespStr), &res); err == nil {
				code, _ := res["code"].(float64)
				msg, _ := res["msg"].(string)
				status, _ := res["STATUS"].(string)

				if code == 0 || strings.EqualFold(msg, "ok") || status == "S" || strings.Contains(strings.ToLower(cmdRespStr), "success") {
					fmt.Fprintf(os.Stderr, "[WM-EXEC] Команда [%s] успешно подтверждена майнером!\n", desc)
					return nil
				}
			}

			if !cand.useB64 {
				break
			}
		}
	}

	return fmt.Errorf("майнер отклонил команду для действия %s", action)
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
		// 1. Проверяем VNish / Braiins OS через FFI[cite: 5]
		f := asic_go.NewMinerFactory().WithIdentificationTimeoutSecs(4)
		miner, err := f.GetMiner(*target)
		f.Close()

		handled := false
		if err == nil {
			if *user != "" && *pass != "" {
				_ = miner.SetAuth(*user, *pass)
			}
			ok, _ := miner.Pause(nil)
			if ok {
				fmt.Fprintf(os.Stderr, "[FFI] Пауза успешно выполнена через asic-rs (VNish/Braiins)\n")
				handled = true
			}
			miner.Close()
		}

		// 2. WhatsMiner: пробуем с p_hash
		if !handled {
			if err := executeWhatsminerSessionCmd(*target, *user, *pass, "stop"); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
		}

	case "resume":
		f := asic_go.NewMinerFactory().WithIdentificationTimeoutSecs(4)
		miner, err := f.GetMiner(*target)
		f.Close()

		handled := false
		if err == nil {
			if *user != "" && *pass != "" {
				_ = miner.SetAuth(*user, *pass)
			}
			ok, _ := miner.Resume(nil)
			if ok {
				fmt.Fprintf(os.Stderr, "[FFI] Запуск успешно выполнен через asic-rs (VNish/Braiins)\n")
				handled = true
			}
			miner.Close()
		}

		if !handled {
			if err := executeWhatsminerSessionCmd(*target, *user, *pass, "start"); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
		}

	case "restart":
		f := asic_go.NewMinerFactory().WithIdentificationTimeoutSecs(4)
		miner, err := f.GetMiner(*target)
		f.Close()

		handled := false
		if err == nil {
			if *user != "" && *pass != "" {
				_ = miner.SetAuth(*user, *pass)
			}
			ok, _ := miner.Restart()
			if ok {
				fmt.Fprintf(os.Stderr, "[FFI] Перезагрузка успешно выполнена через asic-rs (VNish/Braiins)\n")
				handled = true
			}
			miner.Close()
		}

		if !handled {
			if err := executeWhatsminerSessionCmd(*target, *user, *pass, "restart"); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
		}
	}
}
