"""Config flow for ASIC Monitor integration."""
from __future__ import annotations

import logging
from typing import Any
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
import homeassistant.helpers.config_validation as cv

from .const import (
	CONF_PASSWORD,
	CONF_POLL_INTERVAL,
	CONF_SCAN_INTERVAL,
	CONF_SUBNETS,
	CONF_USERNAME,
	DEFAULT_PASSWORD,
	DEFAULT_POLL_INTERVAL,
	DEFAULT_SCAN_INTERVAL,
	DEFAULT_SUBNETS,
	DEFAULT_USERNAME,
	DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


class AsicMonitorConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
	"""Handle a config flow for ASIC Monitor."""

	VERSION = 1

	async def async_step_user(
		self, user_input: dict[str, Any] | None = None
	) -> FlowResult:
		"""Шаг конфигурации пользователем при добавлении подсети."""
		errors: dict[str, str] = {}

		if user_input is not None:
			subnet_val = str(user_input.get(CONF_SUBNETS, "")).strip()
			if not subnet_val:
				errors[CONF_SUBNETS] = "invalid_subnet"
			else:
				await self.async_set_unique_id(subnet_val)
				self._abort_if_unique_id_configured()

				return self.async_create_entry(
					title=f"ASIC Subnet ({subnet_val})",
					data=user_input,
				)

		data_schema = vol.Schema(
			{
				vol.Required(CONF_SUBNETS, default=DEFAULT_SUBNETS): cv.string,
				vol.Required(CONF_USERNAME, default=DEFAULT_USERNAME): cv.string,
				vol.Required(CONF_PASSWORD, default=DEFAULT_PASSWORD): cv.string,
				vol.Required(CONF_POLL_INTERVAL, default=DEFAULT_POLL_INTERVAL): cv.positive_int,
				vol.Required(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): cv.positive_int,
			}
		)

		return self.async_show_form(
			step_id="user",
			data_schema=data_schema,
			errors=errors,
		)

	@staticmethod
	@callback
	def async_get_options_flow(
		config_entry: config_entries.ConfigEntry,
	) -> config_entries.OptionsFlow:
		"""Создание меню параметров 'Настроить'."""
		return AsicMonitorOptionsFlow(config_entry)


class AsicMonitorOptionsFlow(config_entries.OptionsFlow):
	"""Управление параметрами добавленной подсети."""

	def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
		self.config_entry = config_entry

	async def async_step_init(
		self, user_input: dict[str, Any] | None = None
	) -> FlowResult:
		"""Окно изменения параметров."""
		if user_input is not None:
			return self.async_create_entry(title="", data=user_input)

		current = {**self.config_entry.data, **self.config_entry.options}

		# Безопасное извлечение с гарантией от None
		subnets = current.get(CONF_SUBNETS) or DEFAULT_SUBNETS
		username = current.get(CONF_USERNAME) or DEFAULT_USERNAME
		password = current.get(CONF_PASSWORD) or DEFAULT_PASSWORD
		poll_int = current.get(CONF_POLL_INTERVAL) or DEFAULT_POLL_INTERVAL
		scan_int = current.get(CONF_SCAN_INTERVAL) or DEFAULT_SCAN_INTERVAL

		schema = vol.Schema(
			{
				vol.Required(CONF_SUBNETS, default=subnets): cv.string,
				vol.Required(CONF_USERNAME, default=username): cv.string,
				vol.Required(CONF_PASSWORD, default=password): cv.string,
				vol.Required(CONF_POLL_INTERVAL, default=int(poll_int)): cv.positive_int,
				vol.Required(CONF_SCAN_INTERVAL, default=int(scan_int)): cv.positive_int,
			}
		)

		return self.async_show_form(step_id="init", data_schema=schema)