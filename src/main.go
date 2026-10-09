package main

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	CanPause    bool     `json:"can_pause"`
	CanResume   bool     `json:"can_resume"`
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

// aesEncryptPKCS7 шифрует данные AES-256-ECB со стандартным дополнением PKCS#7 (как в Rust asic-rs)
func aesEncryptPKCS7(plain []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	padLen := bs - (len(plain) % bs)
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	plain = append(plain, pad...)

	cipherText := make([]byte, len(plain))
	for start := 0; start < len(plain); start += bs {
		block.Encrypt(cipherText[start:start+bs], plain[start:start+bs])
	}
	return cipherText, nil
}

// sendSingleTCP отправляет 1 JSON-запрос в новом TCP-соединении и читает ответ
func sendSingleTCP(ip string, payload interface{}) (map[string]interface{}, string, error) {
	addr := net.JoinHostPort(ip, "4028")
	conn, err := net.DialTimeout("tcp", addr, 4*time.Second)
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	data = append(data, '\n')

	if _, err := conn.Write(data); err != nil {
		return nil, "", err
	}

	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return nil, "", err
	}
	if n == 0 {
		return nil, "", fmt.Errorf("пустой ответ (сокет закрыт майнером)")
	}

	respText := strings.TrimRight(string(buf[:n]), "\x00\r\n ")
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(respText), &result); err != nil {
		return nil, respText, fmt.Errorf("невалидный JSON: %s", respText)
	}

	return result, respText, nil
}

// getMinerSalt получает постоянный salt майнера в отдельном TCP-соединении
func getMinerSalt(ip string) (string, error) {
	cmds := []map[string]interface{}{
		{"cmd": "get.device.info"},
		{"command": "get_token"},
		{"cmd": "get_token"},
	}

	for _, c := range cmds {
		resp, _, err := sendSingleTCP(ip, c)
		if err != nil || resp == nil {
			continue
		}
		if status, ok := resp["STATUS"].(string); ok && status == "E" {
			continue
		}
		if s, ok := resp["salt"].(string); ok && s != "" {
			return s, nil
		}
		if msgMap, ok := resp["msg"].(map[string]interface{}); ok {
			if s, ok := msgMap["salt"].(string); ok && s != "" {
				return s, nil
			}
		}
		if msgMap, ok := resp["Msg"].(map[string]interface{}); ok {
			if s, ok := msgMap["salt"].(string); ok && s != "" {
				return s, nil
			}
		}
	}
	return "", fmt.Errorf("не удалось получить salt")
}

// tryAsicRsFFI пробует выполнить команду через встроенный Rust FFI (asic-rs)
func tryAsicRsFFI(ip, user, pass, action string) bool {
	f := asic_go.NewMinerFactory().WithIdentificationTimeoutSecs(5)
	defer f.Close()

	// 1) с пользователем из HA, 2) super с паролем из HA, 3) дефолтный super:super, 4) дефолтный admin:admin
	authPairs := []struct{ u, p string }{
		{user, pass},
		{"super", pass},
		{"super", "super"},
		{"admin", "admin"},
	}

	for _, pair := range authPairs {
		miner, err := f.GetMiner(ip)
		if err != nil {
			return false
		}

		if pair.u != "" {
			_ = miner.SetAuth(pair.u, pair.p)
		}

		var ok bool
		var callErr error
		switch action {
		case "stop":
			ok, callErr = miner.Pause(nil)
		case "start":
			ok, callErr = miner.Resume(nil)
		case "restart":
			ok, callErr = miner.Restart()
		}
		miner.Close()

		fmt.Fprintf(os.Stderr, "[FFI-TRY] user=%s, action=%s -> ok=%t, err=%v\n", pair.u, action, ok, callErr)
		if ok {
			return true
		}
	}
	return false
}

// executeWhatsminerV3Direct повторяет логику asic-rs WhatsMinerV3::send_command на чистых TCP-сессиях
func executeWhatsminerV3Direct(ip, user, password, action string) error {
	salt, err := getMinerSalt(ip)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[WM-V3] Получен постоянный salt: %s\n", salt)

	cmdName := "set.miner.service"

	var paramsToTry []string
	if action == "stop" {
		paramsToTry = []string{"stop", "disable"}
	} else if action == "start" {
		paramsToTry = []string{"start", "enable"}
	} else {
		paramsToTry = []string{"restart"}
	}

	accounts := []string{user}
	if user != "super" {
		accounts = append(accounts, "super")
	}

	for _, acc := range accounts {
		for _, pStr := range paramsToTry {
			for mode := 0; mode <= 2; mode++ {
				ts := time.Now().Unix()
				strToHash := fmt.Sprintf("%s%s%s%d", cmdName, password, salt, ts)
				sha256Data := sha256.Sum256([]byte(strToHash))
				token := base64.StdEncoding.EncodeToString(sha256Data[:])[:8]

				var finalParam string
				switch mode {
				case 0:
					finalParam = pStr
				case 1:
					enc, _ := aesEncryptPKCS7([]byte(pStr), sha256Data[:])
					finalParam = base64.StdEncoding.EncodeToString(enc)
				case 2:
					jsonBytes, _ := json.Marshal(pStr)
					enc, _ := aesEncryptPKCS7(jsonBytes, sha256Data[:])
					finalParam = base64.StdEncoding.EncodeToString(enc)
				}

				payload := map[string]interface{}{
					"cmd":     cmdName,
					"ts":      ts,
					"token":   token,
					"account": acc,
					"param":   finalParam,
				}

				pBytes, _ := json.Marshal(payload)
				fmt.Fprintf(os.Stderr, "[WM-V3] Отправка (acc=%s, param=%s, mode=%d): %s\n", acc, pStr, mode, string(pBytes))

				resp, rawStr, err := sendSingleTCP(ip, payload)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[WM-V3] Ответ (acc=%s, mode=%d): %v\n", acc, mode, err)
					time.Sleep(150 * time.Millisecond)
					continue
				}

				fmt.Fprintf(os.Stderr, "[WM-V3] Ответ майнера: %s\n", rawStr)

				code, hasCode := resp["code"].(float64)
				status, _ := resp["STATUS"].(string)
				msg, _ := resp["msg"].(string)

				if (hasCode && code == 0) || status == "S" || strings.EqualFold(msg, "ok") {
					fmt.Fprintf(os.Stderr, "[WM-V3] УСПЕХ! Команда подтверждена майнером!\n")
					return nil
				}
				time.Sleep(150 * time.Millisecond)
			}
		}
	}

	return fmt.Errorf("все комбинации set.miner.service отклонены майнером")
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

		// Для WhatsMiner и моделей с FFI включаем поддержку Pause/Resume
		canPause := caps.Pause
		canResume := caps.Resume
		if strings.EqualFold(data.DeviceInfo.Make, "WhatsMiner") || strings.EqualFold(data.DeviceInfo.Make, "MicroBT") {
			canPause = true
			canResume = true
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
			CanPause:    canPause,
			CanResume:   canResume,
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)

	case "pause":
		if !tryAsicRsFFI(*target, *user, *pass, "stop") {
			if err := executeWhatsminerV3Direct(*target, *user, *pass, "stop"); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
		}

	case "resume":
		if !tryAsicRsFFI(*target, *user, *pass, "start") {
			if err := executeWhatsminerV3Direct(*target, *user, *pass, "start"); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
		}

	case "restart":
		if !tryAsicRsFFI(*target, *user, *pass, "restart") {
			if err := executeWhatsminerV3Direct(*target, *user, *pass, "restart"); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
				os.Exit(1)
			}
		}
	}
}
