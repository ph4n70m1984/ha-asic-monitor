"""The ASIC Monitor integration."""
from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import CONF_POLL_INTERVAL, CONF_SCAN_INTERVAL, CONF_SUBNETS, DOMAIN
from .coordinator import AsicDataCoordinator

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.BINARY_SENSOR, Platform.BUTTON]

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
	"""Set up ASIC Monitor from a config entry."""
	hass.data.setdefault(DOMAIN, {})

	coordinator = AsicDataCoordinator(
		hass=hass,
		subnets=entry.data[CONF_SUBNETS],
		poll_interval=entry.data[CONF_POLL_INTERVAL],
		scan_interval=entry.data[CONF_SCAN_INTERVAL],
	)

	await coordinator.async_config_entry_first_refresh()
	hass.data[DOMAIN][entry.entry_id] = coordinator

	await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
	return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
	"""Unload a config entry."""
	unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
	if unload_ok:
		hass.data[DOMAIN].pop(entry.entry_id)
	return unload_ok