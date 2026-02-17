# Phase 3: Prompt Injection Detection (Tier 2)

> **Goal**: Integrate Meta Prompt Guard 2 (86M parameter model) for detecting prompt injection attacks in both input and output content.
>
> **Depends on**: [Phase 1: Project Setup](./01-project-setup.md)
> **Tier**: 2 — Medium (<50ms on CPU)
> **OWASP**: LLM01 (Prompt Injection)

## Overview

Prompt injection is the most critical threat to LLM agents. An attacker embeds instructions in external content (emails, web pages) that cause the LLM to deviate from its intended behavior.

Meta's **Prompt Guard 2** is an 86M parameter model based on mDeBERTa-v3 that classifies text into:
- **Benign** (label 0): Safe content
- **Injection** (label 1): Direct prompt injection attempts
- **Jailbreak** (label 2): Jailbreak attempts

The model is multilingual (trained on mDeBERTa base), with reasonable performance on Dutch text.

## Model Details

| Property | Value |
|----------|-------|
| Model | `meta-llama/Prompt-Guard-2-86M` |
| Architecture | mDeBERTa-v3-base fine-tuned |
| Parameters | 86M |
| Max tokens | 512 |
| Labels | 0=benign, 1=injection, 2=jailbreak |
| Languages | Multilingual (mDeBERTa base) |
| License | Llama 4 Community License |

## Llama 4 Community License Requirements

Using Prompt Guard 2 requires compliance with the **Llama 4 Community License**:

### Key Requirements

1. **"Built with Llama"** — must be displayed in the application or documentation
2. **700M MAU limit** — usage is restricted to organizations with fewer than 700 million monthly active users
3. **Naming convention** — any model derived from or fine-tuned on Llama models must include "Llama" in its name
4. **Attribution notice** — must include:
   > "Llama 4 is licensed under the Llama 4 Community License, Copyright Meta Platforms, Inc. All Rights Reserved."
5. **Acceptable Use Policy** — must comply with Meta's [Acceptable Use Policy](https://llama.meta.com/llama3/use-policy/)

### Full License Reference

The complete license text is available at: https://llama.meta.com/llama3/license/

For this project:
- The README must include "Built with Llama"
- The license section must include the full attribution notice
- No model fine-tuning is planned, so the naming convention applies only if this changes

## Implementation

### Model Loading & Singleton Caching

```python
# src/llm_io_guard/scanners/prompt_guard.py
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import structlog

from ..scanner import Scanner
from ..models import Action, ScanResult
from ..config import PipelineConfig

logger = structlog.get_logger()

# Labels from the Prompt Guard 2 model
LABELS = {0: "benign", 1: "injection", 2: "jailbreak"}


class PromptGuardScanner(Scanner):
    """Prompt injection detection using Meta Prompt Guard 2."""

    def __init__(self, config: PipelineConfig):
        self._config = config
        self._model = None
        self._tokenizer = None

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

        self._tokenizer = AutoTokenizer.from_pretrained(
            model_name, cache_dir=cache_dir
        )
        self._model = AutoModelForSequenceClassification.from_pretrained(
            model_name, cache_dir=cache_dir
        )
        self._model.eval()  # Set to inference mode

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

        # Use the highest threat score
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
        """Classify a single text chunk. Returns (injection_score, jailbreak_score)."""
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

        return (
            probabilities[1].item(),  # injection
            probabilities[2].item(),  # jailbreak
        )

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
            start += max_tokens - overlap  # Overlap for context continuity

        return chunks
```

### Tokenizer Chunking Strategy

The model has a 512-token window. For content longer than 512 tokens:

1. Tokenize the full content
2. Split into windows of 512 tokens with 50-token overlap
3. Classify each chunk independently
4. Take the **maximum** threat score across all chunks (conservative approach)

The overlap ensures that injection attempts spanning a chunk boundary are still detected.

```
Content: [---------- 1500 tokens ----------]

Chunk 1: [--- 512 tokens ---]
Chunk 2:              [--- 512 tokens ---]        (50-token overlap)
Chunk 3:                           [--- 512 tokens ---]  (50-token overlap)
```

## Confidence Thresholds

| Score Range | Action | Meaning |
|------------|--------|---------|
| ≥0.9 | **BLOCK** | High-confidence prompt injection, reject content |
| 0.7–0.9 | **FLAG** | Suspicious content, log and proceed with caution |
| <0.7 | **PASS** | No significant threat detected |

These thresholds are configurable via `config.yaml`:

```yaml
scanners:
  prompt_guard:
    threshold_block: 0.9
    threshold_flag: 0.7
```

## Multilingual Performance

Prompt Guard 2 is built on mDeBERTa-v3-base, which provides multilingual support:

- **English**: Best performance (primary training language)
- **Dutch**: Reasonable performance via mDeBERTa's multilingual pretraining
  - Direct Dutch injections: Good detection
  - Code-switching (NL/EN mix): Moderate detection
  - Dutch-specific jailbreak patterns may need supplementation via the LLM judge (Tier 3)
- **Other languages**: Variable, depends on mDeBERTa coverage

For Dutch-specific edge cases, the ensemble approach (Prompt Guard 2 + Claude Haiku judge in Tier 3) provides defense in depth.

## Performance

| Metric | Value |
|--------|-------|
| Model size | 86M parameters |
| Inference (CPU) | ~10–30ms per 512-token chunk |
| Inference (GPU) | ~2–5ms per 512-token chunk |
| Memory | ~350MB (model + tokenizer) |
| Startup | ~2–5s (first load, cached after) |

## Known Limitations

1. **Token-level attacks**: Very short injections (1-2 tokens) may not trigger high confidence
2. **Encoded content**: Base64 or Unicode-encoded injections require Tier 1 decoding first
3. **Context-dependent**: Some injections are benign in certain contexts (e.g., security discussions)
4. **Dutch-specific patterns**: May miss Dutch-only jailbreak patterns not in training data

## Implementation Checklist

- [ ] Implement `PromptGuardScanner` with model loading
- [ ] Add singleton caching for model/tokenizer
- [ ] Implement 512-token chunking with overlap
- [ ] Add configurable thresholds
- [ ] Write unit tests with known injection patterns
- [ ] Write tests for Dutch injection attempts
- [ ] Benchmark CPU inference time
- [ ] Add Llama 4 Community License attribution

## Next Phase

→ [Phase 4: PII Detection](./04-pii-detection.md)
