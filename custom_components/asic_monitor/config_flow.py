"""Config flow for ASIC Monitor integration."""
from __future__ import annotations

from typing import Any
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .const import (
	CONF_POLL_INTERVAL,
	CONF_SCAN_INTERVAL,
	CONF_SUBNETS,
	DEFAULT_POLL_INTERVAL,
	DEFAULT_SCAN_INTERVAL,
	DEFAULT_SUBNETS,
	DOMAIN,
)

class AsicMonitorConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
	"""Handle a config flow for ASIC Monitor."""

	VERSION = 1

	async def async_step_user(
		self, user_input: dict[str, Any] | None = None
	) -> FlowResult:
		"""Шаг конфигурации пользователем."""
		errors = {}

		if user_input is not None:
			return self.async_create_entry(
				title=f"ASIC Pool ({user_input[CONF_SUBNETS]})",
				data=user_input,
			)

		data_schema = vol.Schema(
			{
				vol.Required(CONF_SUBNETS, default=DEFAULT_SUBNETS): str,
				vol.Required(CONF_POLL_INTERVAL, default=DEFAULT_POLL_INTERVAL): int,
				vol.Required(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): int,
			}
		)

		return self.async_show_form(
			step_id="user",
			data_schema=data_schema,
			errors=errors,
		)