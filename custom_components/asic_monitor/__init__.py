"""The ASIC Monitor integration."""
from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import (
	CONF_PASSWORD,
	CONF_POLL_INTERVAL,
	CONF_SCAN_INTERVAL,
	CONF_SUBNETS,
	CONF_USERNAME,
	DEFAULT_PASSWORD,
	DEFAULT_POLL_INTERVAL,
	DEFAULT_SCAN_INTERVAL,
	DEFAULT_USERNAME,
	DOMAIN,
)
from .coordinator import AsicDataCoordinator

PLATFORMS: list[Platform] = [
	Platform.SENSOR,
	Platform.BINARY_SENSOR,
	Platform.SWITCH,
	Platform.BUTTON,
]

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
	"""Set up ASIC Monitor from a config entry."""
	hass.data.setdefault(DOMAIN, {})

	cfg = {**entry.data, **entry.options}

	coordinator = AsicDataCoordinator(
		hass=hass,
		subnets=cfg[CONF_SUBNETS],
		poll_interval=cfg.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL),
		scan_interval=cfg.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
		username=cfg.get(CONF_USERNAME, DEFAULT_USERNAME),
		password=cfg.get(CONF_PASSWORD, DEFAULT_PASSWORD),
	)

	await coordinator.async_config_entry_first_refresh()
	hass.data[DOMAIN][entry.entry_id] = coordinator

	await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
	entry.async_on_unload(entry.add_update_listener(async_reload_entry))
	return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
	"""Unload a config entry."""
	unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
	if unload_ok:
		hass.data[DOMAIN].pop(entry.entry_id)
	return unload_ok

async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
	"""Перезагрузка при обновлении параметров в интерфейсе."""
	await async_unload_entry(hass, entry)
	await async_setup_entry(hass, entry)