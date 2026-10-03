"""Button platform for ASIC Monitor."""
from __future__ import annotations

from homeassistant.components.button import ButtonDeviceClass, ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import AsicDataCoordinator
from .sensor import AsicBaseSensor

async def async_setup_entry(
	hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
	"""Настройка кнопок управления."""
	coordinator: AsicDataCoordinator = hass.data[DOMAIN][entry.entry_id]
	known_devices = set()

	def check_and_add():
		new_entities = []
		for ip, data in coordinator.data.items():
			if ip not in known_devices and data.get("can_restart"):
				known_devices.add(ip)
				new_entities.append(AsicRestartButton(coordinator, ip))
		if new_entities:
			async_add_entities(new_entities)

	coordinator.async_add_listener(check_and_add)
	check_and_add()

class AsicRestartButton(AsicBaseSensor, ButtonEntity):
	_attr_name = "Restart"
	_attr_device_class = ButtonDeviceClass.RESTART

	@property
	def unique_id(self) -> str:
		return f"{self.ip}_btn_restart"

	async def async_press(self) -> None:
		"""Вызов команды перезагрузки."""
		await self.coordinator.async_restart_miner(self.ip)