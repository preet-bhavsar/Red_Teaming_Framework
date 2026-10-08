import pandas as pd

from src.trend_tracker import (
    _owasp_metrics,
    owasp_trend_frame,
)

df = pd.read_csv("data/results.csv")

metrics = _owasp_metrics(df)

print("\n===== OWASP METRICS =====")

for owasp_id, data in metrics.items():
    print(
        owasp_id,
        "|",
        data["owasp_category"],
        "| ASR:",
        data["asr"],
        "%",
        "| Block:",
        data["block_rate"],
        "%"
    )

print("\n===== TEST PASSED =====")