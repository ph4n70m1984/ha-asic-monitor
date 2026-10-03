"""Binary Sensor platform for ASIC Monitor."""
from __future__ import annotations

from homeassistant.components.binary_sensor import (
	BinarySensorDeviceClass,
	BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import AsicDataCoordinator
from .sensor import AsicBaseSensor

async def async_setup_entry(
	hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
	"""Настройка бинарных сенсоров."""
	coordinator: AsicDataCoordinator = hass.data[DOMAIN][entry.entry_id]
	known_devices = set()

	def check_and_add():
		new_entities = []
		for ip in coordinator.data:
			if ip not in known_devices:
				known_devices.add(ip)
				new_entities.append(AsicMiningStatusSensor(coordinator, ip))
		if new_entities:
			async_add_entities(new_entities)

	coordinator.async_add_listener(check_and_add)
	check_and_add()

class AsicMiningStatusSensor(AsicBaseSensor, BinarySensorEntity):
	_attr_name = "Mining Status"
	_attr_device_class = BinarySensorDeviceClass.RUNNING

	@property
	def unique_id(self) -> str:
		return f"{self.ip}_mining_status"

	@property
	def is_on(self) -> bool:
		data = self.coordinator.data.get(self.ip)
		return bool(data.get("is_mining", False)) if data else False