from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd
from tqdm import tqdm

from .ollama_client import get_default_client
from . import analyzer
from .utils import setup_logging, DATA_DIR, ensure_dir

log = logging.getLogger(__name__)


def run_attacks(
    dataset_path: Path | None = None,
    raw_results_path: Path | None = None,
) -> Path:
    """
    Load attack_dataset.csv, send prompts to the model via Ollama, and
    write raw_results.csv (before heuristic analysis).
    """
    setup_logging()

    if dataset_path is None:
        dataset_path = DATA_DIR / "attack_dataset.csv"
    if raw_results_path is None:
        raw_results_path = DATA_DIR / "raw_results.csv"

    ensure_dir(raw_results_path.parent)

    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")
    
    log.info("Loading attack dataset from %s", dataset_path)
    try:
        # Try reading with explicit encoding and error handling
        read_params = {
            'encoding': 'utf-8',
            'quotechar': '"',
            'skipinitialspace': True,
            'engine': 'python'  # Use Python engine for better compatibility
        }
        # Add on_bad_lines if available (pandas 1.3+)
        try:
            df = pd.read_csv(dataset_path, **read_params, on_bad_lines='warn')
        except TypeError:
            # Fallback for older pandas versions
            df = pd.read_csv(dataset_path, **read_params)
    except UnicodeDecodeError:
        # Fallback to latin-1 if utf-8 fails
        log.warning("UTF-8 decoding failed, trying latin-1 encoding")
        read_params = {
            'encoding': 'latin-1',
            'quotechar': '"',
            'skipinitialspace': True,
            'engine': 'python'
        }
        try:
            df = pd.read_csv(dataset_path, **read_params, on_bad_lines='warn')
        except TypeError:
            df = pd.read_csv(dataset_path, **read_params)

    if "prompt" not in df.columns:
        raise ValueError("attack_dataset.csv must contain a 'prompt' column.")
    
    log.info("Loaded %d rows from dataset", len(df))
    
    # Verify we have data
    if len(df) == 0:
        raise ValueError("Dataset is empty - no rows found in CSV file")

    client = get_default_client()

    responses: list[str] = []
    total_rows = len(df)
    log.info("Starting to process %d prompts", total_rows)
    
    for idx, (_, row) in enumerate(tqdm(df.iterrows(), total=total_rows, desc="Running attacks"), start=1):
        prompt = str(row["prompt"])
        log.debug("Processing prompt %d/%d: %s", idx, total_rows, prompt[:50] + "..." if len(prompt) > 50 else prompt)
        try:
            resp_text = client.generate(prompt)
        except Exception as e:  # noqa: BLE001
            log.exception("Error calling model for prompt %d: %s", idx, prompt)
            resp_text = f"[ERROR] {e}"
        responses.append(resp_text)
    
    if len(responses) != total_rows:
        log.warning("Mismatch: expected %d responses but got %d", total_rows, len(responses))
    
    log.info("Completed processing %d/%d prompts", len(responses), total_rows)
    df["response"] = responses

    log.info("Writing raw results to %s", raw_results_path)
    df.to_csv(raw_results_path, index=False)
    return raw_results_path


def run_full_pipeline() -> Path:
    """
    End-to-end: dataset -> model calls -> raw_results -> analyzed results.csv
    """
    raw_path = run_attacks()
    analyzed_path = analyzer.analyze_results(raw_path)
    log.info("Full pipeline complete. Final results at %s", analyzed_path)
    return analyzed_path


if __name__ == "__main__":
    run_full_pipeline()


