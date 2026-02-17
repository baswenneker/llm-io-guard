"""Prompt injection detection using Meta Prompt Guard 2."""

from typing import Any

import structlog
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from ..config import PipelineConfig
from ..models import Action, ScanResult
from ..scanner import Scanner

logger = structlog.get_logger()

LABELS = {0: "benign", 1: "injection", 2: "jailbreak"}


class PromptGuardScanner(Scanner):
    """Prompt injection detection using Meta Prompt Guard 2."""

    def __init__(self, config: PipelineConfig):
        self._config = config
        self._model: Any = None
        self._tokenizer: Any = None

    @property
    def name(self) -> str:
        return "prompt_guard"

    @property
    def tier(self) -> int:
        return 2

    async def initialize(self) -> None:
        """Load model and tokenizer (singleton pattern)."""
        if self._model is not None:
            return

        model_name = "meta-llama/Prompt-Guard-2-86M"
        cache_dir = self._config.model_cache_dir

        logger.info("loading_prompt_guard", model=model_name)

        self._tokenizer = AutoTokenizer.from_pretrained(model_name, cache_dir=cache_dir)
        self._model = AutoModelForSequenceClassification.from_pretrained(
            model_name, cache_dir=cache_dir
        )
        self._model.eval()

        logger.info("prompt_guard_loaded", model=model_name)

    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
        if self._model is None or self._tokenizer is None:
            raise RuntimeError("PromptGuardScanner not initialized. Call initialize() first.")

        scanner_config = self._config.get_scanner_config(self.name)
        chunks = self._chunk_text(content)
        max_injection_score = 0.0
        max_jailbreak_score = 0.0

        for chunk in chunks:
            injection_score, jailbreak_score = self._classify_chunk(chunk)
            max_injection_score = max(max_injection_score, injection_score)
            max_jailbreak_score = max(max_jailbreak_score, jailbreak_score)

        threat_score = max(max_injection_score, max_jailbreak_score)
        threat_type = "injection" if max_injection_score >= max_jailbreak_score else "jailbreak"

        if threat_score >= scanner_config.threshold_block:
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
        elif threat_score >= scanner_config.threshold_flag:
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
        tokens = self._tokenizer.encode(text, add_special_tokens=False)

        if len(tokens) <= max_tokens:
            return [text]

        chunks = []
        start = 0
        while start < len(tokens):
            end = start + max_tokens
            chunk_tokens = tokens[start:end]
            chunk_text = self._tokenizer.decode(chunk_tokens)
            chunks.append(chunk_text)
            start += max_tokens - overlap

        return chunks
