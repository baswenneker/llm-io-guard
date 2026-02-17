"""Configuration system for the content safety pipeline."""

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class ScannerConfig(BaseModel):
    """Configuration for a single scanner."""

    enabled: bool = True
    threshold_block: float = 0.9
    threshold_flag: float = 0.7


class PipelineConfig(BaseModel):
    """Root configuration for the content safety pipeline."""

    scanners: dict[str, ScannerConfig] = Field(default_factory=dict)
    tier3_sources: list[str] = Field(default_factory=lambda: ["email", "web", "unknown"])
    log_level: str = "INFO"
    max_content_length: int = 100_000
    model_cache_dir: str = Field(
        default_factory=lambda: os.environ.get(
            "LLM_IO_GUARD_MODEL_DIR", str(Path.home() / ".cache" / "llm_io_guard")
        )
    )

    def is_scanner_enabled(self, scanner_name: str) -> bool:
        """Check if a scanner is enabled (default: True)."""
        if scanner_name not in self.scanners:
            return True
        return self.scanners[scanner_name].enabled

    def get_scanner_config(self, scanner_name: str) -> ScannerConfig:
        """Get configuration for a scanner (returns defaults if not configured)."""
        return self.scanners.get(scanner_name, ScannerConfig())

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PipelineConfig":
        """Load configuration from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls(**data)

    @classmethod
    def from_env(cls) -> "PipelineConfig":
        """Load configuration from environment variables."""
        kwargs: dict[str, Any] = {}
        if log_level := os.environ.get("LLM_IO_GUARD_LOG_LEVEL"):
            kwargs["log_level"] = log_level
        if raw_length := os.environ.get("LLM_IO_GUARD_MAX_CONTENT_LENGTH"):
            kwargs["max_content_length"] = int(raw_length)
        return cls(**kwargs)
