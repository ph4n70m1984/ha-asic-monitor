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
	"strconv"
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

// isAPIGreaterOrEqual сравнивает семантические версии вида "3.0.5" и "3.0.1"
func isAPIGreaterOrEqual(apiVer, targetVer string) bool {
	if apiVer == "" {
		return true // Для современных WhatsMiner без явного флага считаем >= 3.0.5
	}
	cleanVer := strings.TrimPrefix(apiVer, "v")
	v1Parts := strings.Split(cleanVer, ".")
	v2Parts := strings.Split(targetVer, ".")

	maxLen := len(v1Parts)
	if len(v2Parts) > maxLen {
		maxLen = len(v2Parts)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(v1Parts) {
			n1, _ = strconv.Atoi(v1Parts[i])
		}
		if i < len(v2Parts) {
			n2, _ = strconv.Atoi(v2Parts[i])
		}
		if n1 > n2 {
			return true
		}
		if n1 < n2 {
			return false
		}
	}
	return true
}

// executeWhatsminerStrictCmd выполняет строгое разделение по версии API
func executeWhatsminerStrictCmd(ip, user, password, action, apiVer string) error {
	addr := net.JoinHostPort(ip, "4028")
	isModern := isAPIGreaterOrEqual(apiVer, "3.0.5")
	fmt.Fprintf(os.Stderr, "[WM-STRICT] Подключение к %s (API: '%s', Режим modern >= 3.0.5: %t)...\n", addr, apiVer, isModern)

	conn, err := net.DialTimeout("tcp", addr, 4*time.Second)
	if err != nil {
		return fmt.Errorf("ошибка подключения к сокету %s: %w", addr, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	reader := bufio.NewReader(conn)

	// Шаг 1: Запрашиваем токен
	getTokPayload := `{"command":"get_token"}` + "\n"
	if _, err := conn.Write([]byte(getTokPayload)); err != nil {
		return fmt.Errorf("ошибка отправки get_token: %w", err)
	}

	rawResp, err := reader.ReadBytes('\x00')
	if err != nil && len(rawResp) == 0 {
		rawResp, err = reader.ReadBytes('\n')
		if err != nil {
			return fmt.Errorf("ошибка чтения ответа get_token: %w", err)
		}
	}

	respStr := strings.TrimRight(string(rawResp), "\x00\r\n")
	var tokResp TokenResponse
	if err := json.Unmarshal([]byte(respStr), &tokResp); err != nil {
		return fmt.Errorf("ошибка парсинга json get_token: %w", err)
	}

	var activeSalt string
	var msgObj TokenMsg
	if err := json.Unmarshal(tokResp.Msg, &msgObj); err == nil {
		if msgObj.NewSalt != "" {
			activeSalt = msgObj.NewSalt
		} else if msgObj.Salt != "" {
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
		return fmt.Errorf("не удалось извлечь salt из ответа: %s", respStr)
	}

	account := user
	if account == "" || account == "root" {
		account = "admin"
	}

	var payloadMap map[string]interface{}
	var desc string

	if isModern {
		// --- РЕЖИМ API >= 3.0.5: СТРОГО set.miner.service ---
		var param string
		switch action {
		case "stop", "pause", "power_off":
			param = "stop"
		case "start", "resume":
			param = "start"
		default: // restart
			param = "restart"
		}

		cmdName := "set.miner.service"
		ts := time.Now().Unix()
		concat := fmt.Sprintf("%s%s%s%d", cmdName, password, activeSalt, ts)
		hash := sha256.Sum256([]byte(concat))
		b64Token := base64.StdEncoding.EncodeToString(hash[:])
		if len(b64Token) > 8 {
			b64Token = b64Token[:8]
		}

		payloadMap = map[string]interface{}{
			"cmd":     cmdName,
			"ts":      ts,
			"token":   b64Token,
			"account": account,
			"param":   param,
		}
		desc = fmt.Sprintf("set.miner.service param: %s", param)
	} else {
		// --- РЕЖИМ API < 3.0.5: power_off / restart ---
		pHash := sha256Hex(password)
		hexToken := sha256Hex(pHash + activeSalt)

		var legacyCmd string
		switch action {
		case "stop", "pause", "power_off":
			legacyCmd = "power_off"
		case "start", "resume":
			legacyCmd = "restart"
		default: // restart
			legacyCmd = "restart"
		}

		payloadMap = map[string]interface{}{
			"cmd":   legacyCmd,
			"token": hexToken,
		}
		desc = fmt.Sprintf("legacy %s (hex token)", legacyCmd)
	}

	payloadBytes, _ := json.Marshal(payloadMap)
	payloadBytes = append(payloadBytes, '\n')

	fmt.Fprintf(os.Stderr, "[WM-STRICT] Отправка команды [%s]: %s", desc, string(payloadBytes))
	if _, err := conn.Write(payloadBytes); err != nil {
		return fmt.Errorf("ошибка отправки payload: %w", err)
	}

	// Шаг 2: Чтение ответа майнера
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	resRaw, err := reader.ReadBytes('\x00')
	if err != nil && len(resRaw) == 0 {
		resRaw, err = reader.ReadBytes('\n')
	}

	// Разрыв соединения сокетом на WhatsMiner означает успешный перезапуск / остановку демона
	if err != nil || len(resRaw) == 0 {
		fmt.Fprintf(os.Stderr, "[WM-STRICT] Сокет закрыт майнером (команда [%s] успешно выполнена!)\n", desc)
		return nil
	}

	resStr := strings.TrimRight(string(resRaw), "\x00\r\n")
	fmt.Fprintf(os.Stderr, "[WM-STRICT] Ответ майнера: %s\n", resStr)

	var res map[string]interface{}
	if err := json.Unmarshal([]byte(resStr), &res); err == nil {
		code, _ := res["code"].(float64)
		msg, _ := res["msg"].(string)
		status, _ := res["STATUS"].(string)

		if code == 0 || strings.EqualFold(msg, "ok") || status == "S" || strings.Contains(strings.ToLower(resStr), "success") {
			fmt.Fprintf(os.Stderr, "[WM-STRICT] Команда [%s] подтверждена успешно!\n", desc)
			return nil
		}
	}

	return fmt.Errorf("майнер отклонил команду [%s]: %s", desc, resStr)
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
		// 1. Проверяем VNish / Braiins OS через FFI
		f := asic_go.NewMinerFactory().WithIdentificationTimeoutSecs(4)
		miner, err := f.GetMiner(*target)
		f.Close()

		handled := false
		var apiVer string
		if err == nil {
			if *user != "" && *pass != "" {
				_ = miner.SetAuth(*user, *pass)
			}
			if vPtr, err := miner.GetAPIVersion(); err == nil && vPtr != nil {
				apiVer = *vPtr
			}
			ok, _ := miner.Pause(nil)
			if ok {
				fmt.Fprintf(os.Stderr, "[FFI] Пауза успешно выполнена через asic-rs (VNish/Braiins)\n")
				handled = true
			}
			miner.Close()
		}

		// 2. Если не VNish — управляем с проверкой версии API
		if !handled {
			if err := executeWhatsminerStrictCmd(*target, *user, *pass, "stop", apiVer); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
		}

	case "resume":
		// 1. Проверяем VNish / Braiins OS через FFI
		f := asic_go.NewMinerFactory().WithIdentificationTimeoutSecs(4)
		miner, err := f.GetMiner(*target)
		f.Close()

		handled := false
		var apiVer string
		if err == nil {
			if *user != "" && *pass != "" {
				_ = miner.SetAuth(*user, *pass)
			}
			if vPtr, err := miner.GetAPIVersion(); err == nil && vPtr != nil {
				apiVer = *vPtr
			}
			ok, _ := miner.Resume(nil)
			if ok {
				fmt.Fprintf(os.Stderr, "[FFI] Возобновление успешно выполнено через asic-rs (VNish/Braiins)\n")
				handled = true
			}
			miner.Close()
		}

		// 2. WhatsMiner запуск
		if !handled {
			if err := executeWhatsminerStrictCmd(*target, *user, *pass, "start", apiVer); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
		}

	case "restart":
		// 1. Проверяем VNish / Braiins OS через FFI
		f := asic_go.NewMinerFactory().WithIdentificationTimeoutSecs(4)
		miner, err := f.GetMiner(*target)
		f.Close()

		handled := false
		var apiVer string
		if err == nil {
			if *user != "" && *pass != "" {
				_ = miner.SetAuth(*user, *pass)
			}
			if vPtr, err := miner.GetAPIVersion(); err == nil && vPtr != nil {
				apiVer = *vPtr
			}
			ok, _ := miner.Restart()
			if ok {
				fmt.Fprintf(os.Stderr, "[FFI] Перезагрузка успешно выполнена через asic-rs (VNish/Braiins)\n")
				handled = true
			}
			miner.Close()
		}

		// 2. WhatsMiner перезапуск
		if !handled {
			if err := executeWhatsminerStrictCmd(*target, *user, *pass, "restart", apiVer); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
		}
	}
}
