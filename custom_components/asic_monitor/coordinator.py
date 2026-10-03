"""DataUpdateCoordinator for ASIC Monitor."""
from __future__ import annotations

import asyncio
from datetime import timedelta
import json
import logging
import os
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

class AsicDataCoordinator(DataUpdateCoordinator[dict[str, Any]]):
	"""Координатор опроса майнеров."""

	def __init__(
		self,
		hass: HomeAssistant,
		subnets: str,
		poll_interval: int,
		scan_interval: int,
	) -> None:
		super().__init__(
			hass,
			_LOGGER,
			name=DOMAIN,
			update_interval=timedelta(seconds=poll_interval),
		)
		self.subnets = subnets
		self.scan_interval = scan_interval
		self.last_scan_time = 0.0
		self.known_ips: set[str] = set()

		# Путь к скомпилированному Go-бинарнику
		component_dir = os.path.dirname(__file__)
		self.bin_path = os.path.join(component_dir, "bin", "asic_scanner")

	async def _run_cmd(self, *args: str) -> str:
		"""Запуск вспомогательного бинарника."""
		proc = await asyncio.create_subprocess_exec(
			self.bin_path,
			*args,
			stdout=asyncio.subprocess.PIPE,
			stderr=asyncio.subprocess.PIPE,
		)
		stdout, stderr = await proc.communicate()
		if proc.returncode != 0:
			raise UpdateFailed(f"Scanner error: {stderr.decode().strip()}")
		return stdout.decode().strip()

	async def _scan_subnets(self) -> None:
		"""Поиск активных IP в подсетях."""
		try:
			raw = await self._run_cmd("-cmd", "scan", "-target", self.subnets)
			ips = json.loads(raw) or []
			self.known_ips.update(ips)
			_LOGGER.info("ASIC Monitor: found active IPs: %s", self.known_ips)
		except Exception as err:
			_LOGGER.error("Error during subnet scan: %s", err)

	async def async_restart_miner(self, ip: str) -> None:
		"""Отправка команды перезагрузки."""
		await self._run_cmd("-cmd", "restart", "-target", ip)

	async def _async_update_data(self) -> dict[str, Any]:
		"""Периодический опрос телеметрии."""
		now = self.hass.loop.time()
		if now - self.last_scan_time > self.scan_interval or not self.known_ips:
			await self._scan_subnets()
			self.last_scan_time = now

		results: dict[str, Any] = {}

		async def poll_one(ip: str):
			try:
				raw = await self._run_cmd("-cmd", "poll", "-target", ip)
				data = json.loads(raw)
				results[ip] = data
			except Exception as err:
				_LOGGER.debug("Miner at %s unreachable: %s", ip, err)

		# Параллельный опрос всех найденных майнеров
		if self.known_ips:
			await asyncio.gather(*[poll_one(ip) for ip in self.known_ips])

		return results