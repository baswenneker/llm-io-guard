"""Prompt injection detection using Meta Prompt Guard 2."""

import asyncio
import os
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from ..models import Action, ScanResult
from ..scanner import Scanner

try:
    import torch
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
    )

    _HAS_ML_DEPS = True
except ImportError:
    _HAS_ML_DEPS = False

if TYPE_CHECKING:
    from transformers import PreTrainedModel, PreTrainedTokenizerBase

logger = structlog.get_logger()

LABELS = {0: "benign", 1: "injection", 2: "jailbreak"}


class PromptGuardScanner(Scanner):
    """Prompt injection detection using Meta Prompt Guard 2."""

    def __init__(
        self,
        *,
        threshold_block: float = 0.9,
        threshold_flag: float = 0.7,
        model_cache_dir: str | None = None,
    ) -> None:
        """Initialize the Prompt Guard scanner.

        Args:
            threshold_block: Minimum threat score to BLOCK content (default: 0.9).
            threshold_flag: Minimum threat score to FLAG content (default: 0.7).
            model_cache_dir: Directory for caching the model. Falls back to
                ``LLM_IO_GUARD_MODEL_DIR`` env var or ``~/.cache/llm_io_guard``.

        Raises:
            ImportError: If torch/transformers are not installed.
        """
        if not _HAS_ML_DEPS:
            raise ImportError(
                "PromptGuardScanner requires torch and transformers. "
                "Install with: pip install llm-io-guard[ml]"
            )
        self._threshold_block = threshold_block
        self._threshold_flag = threshold_flag
        self._model_cache_dir = model_cache_dir or os.environ.get(
            "LLM_IO_GUARD_MODEL_DIR", str(Path.home() / ".cache" / "llm_io_guard")
        )
        self._model: PreTrainedModel | None = None
        self._tokenizer: PreTrainedTokenizerBase | None = None
        self._init_lock = asyncio.Lock()

    @property
    def name(self) -> str:
        """Return scanner name."""
        return "prompt_guard"

    @property
    def tier(self) -> int:
        """Return scanner tier."""
        return 2

    @property
    def supported_directions(self) -> frozenset[str]:
        """Only supports input direction."""
        return frozenset({"input"})

    async def initialize(self) -> None:
        """Load model and tokenizer (singleton pattern)."""
        async with self._init_lock:
            if self._model is not None:
                return

            model_name = "meta-llama/Prompt-Guard-2-86M"
            model_revision = "a8ded8e697ce7c355e395a0df51f94adb4a2fd27"
            cache_dir = self._model_cache_dir

            logger.info("loading_prompt_guard", model=model_name)

            self._tokenizer = AutoTokenizer.from_pretrained(  # nosec B615 - revision pinned
                model_name, cache_dir=cache_dir, revision=model_revision
            )
            model = AutoModelForSequenceClassification.from_pretrained(  # nosec B615 - revision pinned
                model_name, cache_dir=cache_dir, revision=model_revision
            )
            model.eval()
            self._model = model

            logger.info("prompt_guard_loaded", model=model_name)

    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
        """Scan content for prompt injection and jailbreak attempts."""
        if self._model is None or self._tokenizer is None:
            raise RuntimeError("PromptGuardScanner not initialized. Call initialize() first.")

        chunks = self._chunk_text(content)
        max_injection_score = 0.0
        max_jailbreak_score = 0.0

        for chunk in chunks:
            try:
                injection_score, jailbreak_score = self._classify_chunk(chunk)
            except Exception as e:
                logger.error("prompt_guard_inference_error", error=str(e))
                return ScanResult(
                    scanner_name=self.name,
                    action=Action.BLOCK,
                    confidence=1.0,
                    description=f"Prompt guard inference error (fail-closed): {e}",
                    details={"error": str(e)},
                )
            max_injection_score = max(max_injection_score, injection_score)
            max_jailbreak_score = max(max_jailbreak_score, jailbreak_score)

        threat_score = max(max_injection_score, max_jailbreak_score)
        threat_type = "injection" if max_injection_score >= max_jailbreak_score else "jailbreak"

        if threat_score >= self._threshold_block:
            return ScanResult(
                scanner_name=self.name,
                action=Action.BLOCK,
                confidence=threat_score,
                description=f"Prompt {threat_type} detected (confidence: {threat_score:.2f})",
                details={
                    "threat_type": threat_type,
                    "injection_score": max_injection_score,
                    "jailbreak_score": max_jailbreak_score,
                    "chunks_analyzed": len(chunks),
                },
            )
        elif threat_score >= self._threshold_flag:
            return ScanResult(
                scanner_name=self.name,
                action=Action.FLAG,
                confidence=threat_score,
                description=f"Possible prompt {threat_type} (confidence: {threat_score:.2f})",
                details={
                    "threat_type": threat_type,
                    "injection_score": max_injection_score,
                    "jailbreak_score": max_jailbreak_score,
                    "chunks_analyzed": len(chunks),
                },
            )
        else:
            return ScanResult(
                scanner_name=self.name,
                action=Action.PASS,
                confidence=threat_score,
                description="No prompt injection detected",
                details={
                    "injection_score": max_injection_score,
                    "jailbreak_score": max_jailbreak_score,
                    "chunks_analyzed": len(chunks),
                },
            )

    def _classify_chunk(self, text: str) -> tuple[float, float]:
        """Classify a single text chunk."""
        assert self._tokenizer is not None  # noqa: S101  # nosec B101
        assert self._model is not None  # noqa: S101  # nosec B101
        inputs = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True,
        )

        with torch.no_grad():
            outputs = self._model(**inputs)
            probabilities = torch.softmax(outputs.logits, dim=-1)[0]

        return (probabilities[1].item(), probabilities[2].item())

    def _chunk_text(self, text: str, max_tokens: int = 512, overlap: int = 50) -> list[str]:
        """Split text into overlapping chunks for the model's token limit."""
        assert self._tokenizer is not None  # noqa: S101  # nosec B101
        tokens = self._tokenizer.encode(text, add_special_tokens=False)

        if len(tokens) <= max_tokens:
            return [text]

        chunks = []
        start = 0
        while start < len(tokens):
            end = start + max_tokens
            chunk_tokens = tokens[start:end]
            chunk_text = str(self._tokenizer.decode(chunk_tokens))
            chunks.append(chunk_text)
            start += max_tokens - overlap

        return chunks
