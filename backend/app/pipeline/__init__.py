"""Finding normalization, de-duplication, and cross-tool correlation pipeline."""

from app.pipeline.correlate import correlate_findings
from app.pipeline.normalize import normalize_observation

__all__ = ["correlate_findings", "normalize_observation"]
