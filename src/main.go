package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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

func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func encryptParam(plainText string, aesKey []byte) (string, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	padded := pkcs7Padding([]byte(plainText), aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	iv := make([]byte, aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func isAPIGreaterOrEqual(apiVer, targetVer string) bool {
	if apiVer == "" {
		return true
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

func executeWhatsminerStrictControl(ip, user, password, action, apiVer string) error {
	addr := net.JoinHostPort(ip, "4028")
	isModern := isAPIGreaterOrEqual(apiVer, "3.0.5")
	fmt.Fprintf(os.Stderr, "[WM-STRICT] Подключение к %s (API: '%s', Режим modern >= 3.0.5: %t)...\n", addr, apiVer, isModern)

	account := user
	if account == "" || account == "root" {
		account = "admin"
	}

	// Список команд кандидатов для выполнения
	type targetCmd struct {
		cmd      string
		rawParam string
		useAES   bool
	}

	var targets []targetCmd
	if isModern {
		if action == "stop" || action == "pause" || action == "power_off" {
			targets = []targetCmd{
				{cmd: "set.power_off", rawParam: "", useAES: false},
				{cmd: "set.miner.power_off", rawParam: "", useAES: false},
				{cmd: "set.miner.service", rawParam: "stop", useAES: false},
				{cmd: "set.miner.service", rawParam: `"stop"`, useAES: true},
				{cmd: "set.miner.power", rawParam: `"off"`, useAES: true},
			}
		} else if action == "start" || action == "resume" {
			targets = []targetCmd{
				{cmd: "set.miner.service", rawParam: "start", useAES: false},
				{cmd: "set.miner.service", rawParam: `"start"`, useAES: true},
				{cmd: "set.miner.power_on", rawParam: "", useAES: false},
				{cmd: "set.miner.power", rawParam: `"on"`, useAES: true},
			}
		} else { // restart
			targets = []targetCmd{
				{cmd: "set.miner.service", rawParam: "restart", useAES: false},
				{cmd: "set.miner.service", rawParam: `"restart"`, useAES: true},
				{cmd: "set.miner.restart", rawParam: "", useAES: false},
			}
		}
	} else {
		// API < 3.0.5
		legacyCmd := "power_off"
		if action == "start" || action == "resume" || action == "restart" {
			legacyCmd = "restart"
		}
		targets = []targetCmd{
			{cmd: legacyCmd, rawParam: "", useAES: false},
		}
	}

	for _, tc := range targets {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		reader := bufio.NewReader(conn)

		// 1. Запрашиваем токен
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
			conn.Close()
			continue
		}

		var payloadBytes []byte
		if isModern {
			ts := time.Now().Unix()
			concat := fmt.Sprintf("%s%s%s%d", tc.cmd, password, activeSalt, ts)
			shaKey := sha256.Sum256([]byte(concat))

			b64Token := base64.StdEncoding.EncodeToString(shaKey[:])
			if len(b64Token) > 8 {
				b64Token = b64Token[:8]
			}

			reqMap := map[string]interface{}{
				"cmd":     tc.cmd,
				"account": account,
				"ts":      ts,
				"token":   b64Token,
			}

			if tc.rawParam != "" {
				if tc.useAES {
					encParam, err := encryptParam(tc.rawParam, shaKey[:])
					if err != nil {
						conn.Close()
						continue
					}
					reqMap["param"] = encParam
				} else {
					reqMap["param"] = tc.rawParam
				}
			}
			payloadBytes, _ = json.Marshal(reqMap)
		} else {
			pHash := sha256Hex(password)
			hexToken := sha256Hex(pHash + activeSalt)
			payloadBytes, _ = json.Marshal(map[string]interface{}{
				"cmd":   tc.cmd,
				"token": hexToken,
			})
		}
		payloadBytes = append(payloadBytes, '\n')

		fmt.Fprintf(os.Stderr, "[WM-STRICT] Пробуем команду '%s' (useAES=%t): %s", tc.cmd, tc.useAES, string(payloadBytes))
		if _, err := conn.Write(payloadBytes); err != nil {
			conn.Close()
			continue
		}

		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		resRaw, err := reader.ReadBytes('\x00')
		if err != nil && len(resRaw) == 0 {
			resRaw, err = reader.ReadBytes('\n')
		}
		conn.Close()

		if err != nil || len(resRaw) == 0 {
			fmt.Fprintf(os.Stderr, "[WM-STRICT] Команда '%s' сбросила сокет (отклонена майнером)\n", tc.cmd)
			continue
		}

		cmdRespStr := strings.TrimRight(string(resRaw), "\x00\r\n")
		fmt.Fprintf(os.Stderr, "[WM-STRICT] Ответ майнера: %s\n", cmdRespStr)

		var res map[string]interface{}
		if err := json.Unmarshal([]byte(cmdRespStr), &res); err == nil {
			code, _ := res["code"].(float64)
			msg, _ := res["msg"].(string)
			status, _ := res["STATUS"].(string)

			if code == 0 || strings.EqualFold(msg, "ok") || status == "S" || strings.Contains(strings.ToLower(cmdRespStr), "success") {
				fmt.Fprintf(os.Stderr, "[WM-STRICT] Команда '%s' успешно принята и подтверждена майнером!\n", tc.cmd)
				return nil
			}
		}
	}

	return fmt.Errorf("майнер отклонил все варианты команд управления для API %s", apiVer)
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

		// 2. WhatsMiner строго по версии API
		if !handled {
			if err := executeWhatsminerStrictControl(*target, *user, *pass, "stop", apiVer); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
		}

	case "resume":
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

		if !handled {
			if err := executeWhatsminerStrictControl(*target, *user, *pass, "start", apiVer); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
		}

	case "restart":
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
				fmt.Fprintf(os.Stderr, "[FFI] Рестарт успешно выполнен через asic-rs (VNish/Braiins)\n")
				handled = true
			}
			miner.Close()
		}

		if !handled {
			if err := executeWhatsminerStrictControl(*target, *user, *pass, "restart", apiVer); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
		}
	}
}
