"""Tests for the configuration system."""

from pathlib import Path

from llm_io_guard.config import PipelineConfig, ScannerConfig


class TestScannerConfig:
    """Tests for ScannerConfig."""

    def test_defaults(self):
        config = ScannerConfig()
        assert config.enabled is True
        assert config.threshold_block == 0.9
        assert config.threshold_flag == 0.7

    def test_custom_values(self):
        config = ScannerConfig(enabled=False, threshold_block=0.8, threshold_flag=0.5)
        assert config.enabled is False
        assert config.threshold_block == 0.8
        assert config.threshold_flag == 0.5


class TestPipelineConfig:
    """Tests for PipelineConfig."""

    def test_defaults(self):
        config = PipelineConfig()
        assert config.scanners == {}
        assert config.tier3_sources == ["email", "web", "unknown"]
        assert config.log_level == "INFO"
        assert config.max_content_length == 100_000

    def test_is_scanner_enabled_default(self):
        config = PipelineConfig()
        assert config.is_scanner_enabled("unknown_scanner") is True

    def test_is_scanner_enabled_explicit(self):
        config = PipelineConfig(
            scanners={"test_scanner": ScannerConfig(enabled=False)},
        )
        assert config.is_scanner_enabled("test_scanner") is False

    def test_is_scanner_enabled_true(self):
        config = PipelineConfig(
            scanners={"test_scanner": ScannerConfig(enabled=True)},
        )
        assert config.is_scanner_enabled("test_scanner") is True

    def test_get_scanner_config_default(self):
        config = PipelineConfig()
        scanner_config = config.get_scanner_config("missing")
        assert scanner_config.enabled is True
        assert scanner_config.threshold_block == 0.9

    def test_get_scanner_config_explicit(self):
        config = PipelineConfig(
            scanners={"custom": ScannerConfig(threshold_block=0.8)},
        )
        scanner_config = config.get_scanner_config("custom")
        assert scanner_config.threshold_block == 0.8

    def test_from_yaml(self, tmp_path: Path):
        yaml_content = """\
log_level: DEBUG
max_content_length: 50000
scanners:
  test_scanner:
    enabled: true
    threshold_block: 0.85
    threshold_flag: 0.6
tier3_sources:
  - email
"""
        yaml_file = tmp_path / "test_config.yaml"
        yaml_file.write_text(yaml_content)

        config = PipelineConfig.from_yaml(yaml_file)
        assert config.log_level == "DEBUG"
        assert config.max_content_length == 50000
        assert config.tier3_sources == ["email"]
        assert config.scanners["test_scanner"].threshold_block == 0.85

    def test_from_yaml_empty(self, tmp_path: Path):
        yaml_file = tmp_path / "empty.yaml"
        yaml_file.write_text("")

        config = PipelineConfig.from_yaml(yaml_file)
        assert config.log_level == "INFO"
        assert config.scanners == {}

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("LLM_IO_GUARD_LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("LLM_IO_GUARD_MAX_CONTENT_LENGTH", "50000")

        config = PipelineConfig.from_env()
        assert config.log_level == "DEBUG"
        assert config.max_content_length == 50000

    def test_from_env_no_vars(self, monkeypatch):
        monkeypatch.delenv("LLM_IO_GUARD_LOG_LEVEL", raising=False)
        monkeypatch.delenv("LLM_IO_GUARD_MAX_CONTENT_LENGTH", raising=False)

        config = PipelineConfig.from_env()
        assert config.log_level == "INFO"
        assert config.max_content_length == 100_000

    def test_from_default_yaml(self):
        config_path = Path(__file__).parent.parent / "config" / "default.yaml"
        config = PipelineConfig.from_yaml(config_path)
        assert config.is_scanner_enabled("prompt_guard") is True
        assert config.scanners["llm_judge"].threshold_block == 0.8
