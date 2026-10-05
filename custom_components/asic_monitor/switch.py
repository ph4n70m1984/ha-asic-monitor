"""Switch platform for ASIC Monitor."""
from __future__ import annotations

from typing import Any
from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import AsicDataCoordinator

async def async_setup_entry(
	hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
	"""Настройка переключателей."""
	coordinator: AsicDataCoordinator = hass.data[DOMAIN][entry.entry_id]
	known_devices: set[str] = set()

	def check_and_add():
		new_entities = []
		for ip in coordinator.data:
			if ip not in known_devices:
				known_devices.add(ip)
				new_entities.append(AsicMiningSwitch(coordinator, ip))
		if new_entities:
			async_add_entities(new_entities)

	coordinator.async_add_listener(check_and_add)
	check_and_add()

class AsicMiningSwitch(CoordinatorEntity[AsicDataCoordinator], SwitchEntity):
	"""Переключатель работы майнера (Start / Stop)."""

	_attr_has_entity_name = True
	_attr_name = "Mining"
	_attr_icon = "mdi:pickaxe"

	def __init__(self, coordinator: AsicDataCoordinator, ip: str) -> None:
		super().__init__(coordinator)
		self.ip = ip
		self._attr_unique_id = f"{ip}_mining"
		self._override_state: bool | None = None

	@property
	def device_info(self):
		data = self.coordinator.data.get(self.ip, {})
		sw = data.get("firmware", "WhatsMiner Stock")
		if api_ver := data.get("api_version"):
			sw = f"{sw} (API {api_ver})"

		return {
			"identifiers": {(DOMAIN, self.ip)},
			"name": f"ASIC {self.ip}",
			"manufacturer": data.get("make", "WhatsMiner"),
			"model": data.get("model", "Miner"),
			"sw_version": sw,
		}

	@property
	def available(self) -> bool:
		return self.ip in self.coordinator.data

	@property
	def is_on(self) -> bool:
		if self._override_state is not None:
			return self._override_state
		data = self.coordinator.data.get(self.ip)
		if not data:
			return False
		if data.get("hashrate_th", 0) > 0.1:
			return True
		return bool(data.get("is_mining", False))

	async def async_turn_on(self, **kwargs: Any) -> None:
		"""Запуск майнинга."""
		self._override_state = True
		self.async_write_ha_state()
		try:
			await self.coordinator.async_resume_miner(self.ip)
		finally:
			self._override_state = None

	async def async_turn_off(self, **kwargs: Any) -> None:
		"""Остановка (пауза) майнинга."""
		self._override_state = False
		self.async_write_ha_state()
		try:
			await self.coordinator.async_pause_miner(self.ip)
		finally:
			self._override_state = None