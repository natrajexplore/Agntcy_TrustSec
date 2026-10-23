# Vendored from RuleGate (crewai_fw_chg_reviewer @ 6ce533b) — deterministic core only, no CrewAI/LLM.
"""Vendor parsers. Each exposes ``load_offline(path, device_group=None) -> list[NormalizedRule]``."""

from agenttrustsec.review.parsers import ftd_fmc, panos

LOADERS = {"panos": panos.load_offline, "ftd": ftd_fmc.load_offline}
