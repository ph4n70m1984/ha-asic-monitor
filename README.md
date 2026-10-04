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

Для сборки `asic_scanner_amd64` используется **статическая линковка musl**.

### Требования

- Linux x86_64
- Go **1.23+**
- Rust / Cargo
- CGO
- Git
- `build-essential`

### Подготовка окружения

#### 1. Установка системных утилит и Rust

```bash
sudo apt update && sudo apt install -y curl build-essential git

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

source "$HOME/.cargo/env"

rustup target add x86_64-unknown-linux-musl
```

#### 2. Загрузка автономного musl-компилятора

```bash
cd /tmp

curl -OL https://musl.cc/x86_64-linux-musl-cross.tgz

tar -xf x86_64-linux-musl-cross.tgz
```

### Шаг 1. Сборка Rust FFI

Клонируйте `asic-rs`:

```bash
cd /tmp

git clone --depth 1 https://github.com/256foundation/asic-rs.git

cd asic-rs
```

Настройте musl-компилятор:

```bash
export CC_x86_64_unknown_linux_musl=/tmp/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc

export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=/tmp/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc
```

Соберите релизную версию:

```bash
cargo build \
  --release \
  --target x86_64-unknown-linux-musl \
  -p asic-rs-ffi
```

После успешной сборки библиотека будет находиться здесь:

```text
/tmp/asic-rs/target/x86_64-unknown-linux-musl/release/libasic_rs_ffi.a
```

### Шаг 2. Сборка Go-бинарника

Перейдите в каталог исходников проекта:

```bash
cd "<путь_к_проекту>/ha-asic-monitor/src"
```

Настройте CGO и musl-компилятор:

```bash
export CC=/tmp/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc
export CXX=/tmp/x86_64-linux-musl-cross/bin/x86_64-linux-musl-g++

export CGO_ENABLED=1

export CGO_LDFLAGS="-L/tmp/asic-rs/target/x86_64-unknown-linux-musl/release"
```

Соберите статически связанный бинарник:

```bash
go build \
  -ldflags="-s -w -extldflags '-static'" \
  -o ../custom_components/asic_monitor/bin/asic_scanner_amd64
```

Готовый бинарник:

```text
custom_components/
└── asic_monitor/
    └── bin/
        └── asic_scanner_amd64
```

### Проверка

Проверить полученный бинарник:

```bash
file ../custom_components/asic_monitor/bin/asic_scanner_amd64
```

Для статической сборки ожидается вывод с указанием:

```text
statically linked
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

Мониторинг и работа с ASIC основаны на проекте **[`asic-rs`](https://github.com/256foundation/asic-rs)**.

---

## 📄 License

MIT

---

**ASIC Monitor** — мониторинг ASIC-майнеров прямо в Home Assistant. ⚡🏠