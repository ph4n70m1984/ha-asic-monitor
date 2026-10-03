# ASIC Monitor for Home Assistant

**HACS-интеграция для автоматического обнаружения, мониторинга и управления ASIC-майнерами в локальной сети.**

Использует высокопроизводительное ядро [`asic-rs`](https://github.com/256foundation/asic-rs) через Go FFI и предоставляет данные ASIC непосредственно в **Home Assistant**.

## ✨ Возможности

- 🔎 **Автоматическое обнаружение ASIC**
  - сканирование одной или нескольких подсетей;
  - поддержка CIDR;
  - автоматический поиск новых устройств.

- 📊 **Мониторинг**
  - ⚡ Хэшрейт — TH/s
  - 🔌 Потребляемая мощность — W
  - 🌡️ Максимальная температура чипов — °C
  - 🌐 URL активного пула
  - 👤 Worker / User
  - ⛏️ Статус майнинга — ON/OFF

- 🎛️ **Управление**
  - 🔄 Перезагрузка ASIC, если функция поддерживается моделью.

- 🏠 **Home Assistant**
  - автоматическое создание устройств и сенсоров;
  - поддержка Dashboard, Automation и Scripts;
  - настройка через стандартный интерфейс Home Assistant.

---

## 📦 Установка через HACS

1. Откройте **HACS → Integrations**.
2. Нажмите **⋮ → Custom repositories**.
3. Вставьте URL репозитория.
4. Выберите категорию **Integration**.
5. Нажмите **Add**.
6. Найдите **ASIC Monitor** и нажмите **Download**.
7. Перезагрузите Home Assistant.

---

## ⚙️ Настройка

Перейдите:

**Settings → Devices & Services → Add Integration**

Найдите **ASIC Monitor** и укажите параметры:

| Параметр | Описание | По умолчанию |
|---|---|---:|
| **Subnets** | Подсети для поиска ASIC в формате CIDR | — |
| **Telemetry interval** | Интервал обновления телеметрии | `20 сек` |
| **Discovery interval** | Интервал поиска новых устройств | `900 сек` |

### Пример

```text
192.168.1.0/24, 10.0.1.0/24
```

Можно указать несколько подсетей через запятую.

---

## 📊 Сущности Home Assistant

Для каждого обнаруженного ASIC создаются соответствующие сущности:

| Сущность | Значение |
|---|---|
| **Hashrate** | Хэшрейт, TH/s |
| **Power** | Потребляемая мощность, W |
| **Max Temperature** | Максимальная температура чипов, °C |
| **Pool URL** | Активный пул |
| **Worker** | Имя воркера / пользователя |
| **Mining Status** | Статус майнинга |
| **Restart** | Перезагрузка устройства* |

\* Доступно только для моделей, поддерживающих соответствующую команду.

---

## 🛠️ Сборка для разработчиков

Для сборки `asic_scanner_amd64` требуются:

- Go **1.23+**
- Rust / Cargo
- CGO
- Linux/amd64 toolchain

### 1. Сборка Rust FFI

```bash
git clone --depth 1 https://github.com/256foundation/asic-rs.git /tmp/asic-rs

cd /tmp/asic-rs

cargo build --release -p asic-rs-ffi
```

### 2. Сборка Go-бинарника

```bash
cd ha-asic-monitor/src

export CGO_ENABLED=1
export CGO_LDFLAGS="-L/tmp/asic-rs/target/release"

go build \
  -ldflags="-s -w" \
  -o ../custom_components/asic_monitor/bin/asic_scanner_amd64 \
  main.go

chmod +x ../custom_components/asic_monitor/bin/asic_scanner_amd64
```

---

## 📋 Требования

- Home Assistant
- HACS
- ASIC-майнеры в локальной сети
- Сетевой доступ Home Assistant к ASIC
- Поддерживаемая модель ASIC

Поддержка конкретных функций зависит от модели устройства и установленной прошивки.

---

## 🙏 Credits

Мониторинг и работа с ASIC основаны на проекте **[asic-rs](https://github.com/256foundation/asic-rs)**.

---

## 📄 License

MIT

---

**ASIC Monitor** — мониторинг ASIC-майнеров прямо в Home Assistant. ⚡🏠