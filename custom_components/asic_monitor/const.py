"""Constants for the ASIC Monitor integration."""

DOMAIN = "asic_monitor"

CONF_SUBNETS = "subnets"
CONF_SCAN_INTERVAL = "scan_interval"
CONF_POLL_INTERVAL = "poll_interval"

DEFAULT_SUBNETS = "192.168.1.0/24"
DEFAULT_SCAN_INTERVAL = 900  # 15 минут в секундах
DEFAULT_POLL_INTERVAL = 20   # 20 секунд