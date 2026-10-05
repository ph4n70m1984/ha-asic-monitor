"""Sensor platform for ASIC Monitor."""
from __future__ import annotations

from homeassistant.components.sensor import (
	SensorDeviceClass,
	SensorEntity,
	SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfPower, UnitOfTemperature, EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import AsicDataCoordinator

async def async_setup_entry(
	hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
	"""Настройка сенсоров."""
	coordinator: AsicDataCoordinator = hass.data[DOMAIN][entry.entry_id]
	known_devices: set[str] = set()

	def check_and_add():
		new_entities = []
		for ip, data in coordinator.data.items():
			if ip not in known_devices:
				known_devices.add(ip)
				new_entities.extend([
					AsicHashrateSensor(coordinator, ip),
					AsicPowerSensor(coordinator, ip),
					AsicChipTempSensor(coordinator, ip),
					AsicPoolUrlSensor(coordinator, ip),
					AsicPoolUserSensor(coordinator, ip),
					AsicApiVersionSensor(coordinator, ip),
				])
		if new_entities:
			async_add_entities(new_entities)

	coordinator.async_add_listener(check_and_add)
	check_and_add()

class AsicBaseSensor(CoordinatorEntity[AsicDataCoordinator], SensorEntity):
	"""Базовый класс для сенсоров майнера."""

	def __init__(self, coordinator: AsicDataCoordinator, ip: str) -> None:
		super().__init__(coordinator)
		self.ip = ip
		self._attr_has_entity_name = True

	@property
	def device_info(self):
		data = self.coordinator.data.get(self.ip, {})
		sw = data.get("firmware", "Stock")
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

class AsicHashrateSensor(AsicBaseSensor):
	_attr_name = "Hashrate"
	_attr_native_unit_of_measurement = "TH/s"
	_attr_state_class = SensorStateClass.MEASUREMENT

	@property
	def unique_id(self) -> str:
		return f"{self.ip}_hashrate"

	@property
	def native_value(self) -> float | None:
		data = self.coordinator.data.get(self.ip)
		return round(data["hashrate_th"], 2) if data and "hashrate_th" in data else None

class AsicPowerSensor(AsicBaseSensor):
	_attr_name = "Power"
	_attr_device_class = SensorDeviceClass.POWER
	_attr_native_unit_of_measurement = UnitOfPower.WATT
	_attr_state_class = SensorStateClass.MEASUREMENT

	@property
	def unique_id(self) -> str:
		return f"{self.ip}_power"

	@property
	def native_value(self) -> float | None:
		data = self.coordinator.data.get(self.ip)
		return data.get("wattage") if data else None

class AsicChipTempSensor(AsicBaseSensor):
	_attr_name = "Max Chip Temperature"
	_attr_device_class = SensorDeviceClass.TEMPERATURE
	_attr_native_unit_of_measurement = UnitOfTemperature.CELSIUS
	_attr_state_class = SensorStateClass.MEASUREMENT

	@property
	def unique_id(self) -> str:
		return f"{self.ip}_chip_temp_max"

	@property
	def native_value(self) -> float | None:
		data = self.coordinator.data.get(self.ip)
		if data and data.get("max_chip_temp") is not None:
			return round(data["max_chip_temp"], 1)
		return None

class AsicPoolUrlSensor(AsicBaseSensor):
	_attr_name = "Pool URL"
	_attr_icon = "mdi:server-network"

	@property
	def unique_id(self) -> str:
		return f"{self.ip}_pool_url"

	@property
	def native_value(self) -> str | None:
		data = self.coordinator.data.get(self.ip)
		return data.get("pool_url") if data else None

class AsicPoolUserSensor(AsicBaseSensor):
	_attr_name = "Pool Worker / User"
	_attr_icon = "mdi:account-hard-hat"

	@property
	def unique_id(self) -> str:
		return f"{self.ip}_pool_user"

	@property
	def native_value(self) -> str | None:
		data = self.coordinator.data.get(self.ip)
		return data.get("pool_user") if data else None

class AsicApiVersionSensor(AsicBaseSensor):
	"""Сенсор версии API майнера."""

	_attr_name = "API Version"
	_attr_icon = "mdi:code-json"
	_attr_entity_category = EntityCategory.DIAGNOSTIC

	@property
	def unique_id(self) -> str:
		return f"{self.ip}_api_version"

	@property
	def native_value(self) -> str | None:
		data = self.coordinator.data.get(self.ip)
		return data.get("api_version") if data else None