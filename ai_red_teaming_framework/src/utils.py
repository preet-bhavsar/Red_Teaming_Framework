import logging
from pathlib import Path
from typing import Union


def setup_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )


def ensure_dir(path: Union[str, Path]) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def is_empty_csv_file(path: Union[str, Path]) -> bool:
    """
    True if `path` doesn't exist yet, or exists but has no real
    content (0 bytes, or whitespace only).

    This is the "fresh install / no runs yet" case and should be
    treated as "no data" — NOT as a parse error. A plain
    `pd.read_csv()` on a 0-byte file raises
    `pandas.errors.EmptyDataError: No columns to parse from file`,
    which is the bug behind the "Could not read run_history.csv"
    error banner. Callers should check this first and only call
    `pd.read_csv` once they know there's actual content to parse.
    """

    p = Path(path)

    if not p.exists():
        return True

    try:
        return p.stat().st_size == 0 or not p.read_text(
            encoding="utf-8", errors="ignore"
        ).strip()
    except Exception:
        # If we can't even stat/read it, let the caller's own
        # pd.read_csv call surface the real error instead of
        # silently swallowing it here.
        return False


DATA_DIR = Path(__file__).resolve().parent.parent / "data"
RUN_HISTORY_PATH = DATA_DIR / "run_history.csv"




