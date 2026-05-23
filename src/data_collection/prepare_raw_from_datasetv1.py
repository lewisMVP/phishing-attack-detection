import argparse
import csv
import os
import random
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from bs4 import BeautifulSoup


LABEL_RE = re.compile(r"^\s*Label\s*:\s*([01])\s*$", re.IGNORECASE)
URL_RE = re.compile(r"^\s*Original URL\s*:\s*(.+?)\s*$", re.IGNORECASE)


@dataclass(frozen=True)
class Sample:
    sample_dir: Path
    label: int
    original_url: Optional[str]
    screenshot_path: Path
    html_path: Optional[Path]


def _read_metadata(metadata_path: Path) -> tuple[Optional[int], Optional[str]]:
    label: Optional[int] = None
    url: Optional[str] = None
    try:
        with metadata_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if label is None:
                    m = LABEL_RE.match(line)
                    if m:
                        label = int(m.group(1))
                        continue
                if url is None:
                    m = URL_RE.match(line)
                    if m:
                        url = m.group(1).strip()
                        continue
    except FileNotFoundError:
        return None, None
    return label, url


def iter_datasetv1_samples(dataset_dir: Path) -> Iterable[Sample]:
    for entry in dataset_dir.iterdir():
        if not entry.is_dir():
            continue

        metadata_path = entry / "metadata.txt"
        label, original_url = _read_metadata(metadata_path)
        if label not in (0, 1):
            continue

        screenshot_path = entry / "screenshot.png"
        if not screenshot_path.exists():
            continue

        html_path = entry / "page.html"
        if not html_path.exists():
            html_path = None

        yield Sample(
            sample_dir=entry,
            label=label,
            original_url=original_url,
            screenshot_path=screenshot_path,
            html_path=html_path,
        )


def html_to_visible_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.extract()
    text = soup.get_text(separator=" ")
    return " ".join(text.split()).strip()


def ensure_empty_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare balanced data/raw-like folders from data/DatasetV1.\n"
            "Outputs html/png/txt with naming: {label}_{index}.* where label 1=phishing, 0=benign."
        )
    )
    parser.add_argument(
        "--dataset-dir",
        default="data/DatasetV1",
        help="Input DatasetV1 directory (default: data/DatasetV1).",
    )
    parser.add_argument(
        "--output-dir",
        default="data/raw_from_datasetv1",
        help="Output base directory (default: data/raw_from_datasetv1).",
    )
    parser.add_argument(
        "--mode",
        choices=["balanced", "all"],
        default="balanced",
        help=(
            "Export mode. 'balanced' exports min(#benign,#phishing) per class. "
            "'all' exports all available samples (default: balanced)."
        ),
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for shuffling (default: 42).",
    )
    parser.add_argument(
        "--limit-per-class",
        type=int,
        default=0,
        help="Optional cap per class after balancing (0 = no cap).",
    )
    parser.add_argument(
        "--require-html",
        action="store_true",
        help="Only include samples that have page.html.",
    )
    parser.add_argument(
        "--clear-output",
        action="store_true",
        help="Delete output-dir before writing.",
    )

    args = parser.parse_args()

    dataset_dir = Path(args.dataset_dir)
    output_dir = Path(args.output_dir)

    if not dataset_dir.exists():
        raise SystemExit(f"Dataset dir not found: {dataset_dir}")

    out_html = output_dir / "html"
    out_images = output_dir / "images"
    out_text = output_dir / "text"

    if args.clear_output:
        ensure_empty_dir(output_dir)
    else:
        output_dir.mkdir(parents=True, exist_ok=True)

    out_html.mkdir(parents=True, exist_ok=True)
    out_images.mkdir(parents=True, exist_ok=True)
    out_text.mkdir(parents=True, exist_ok=True)

    benign: list[Sample] = []
    phishing: list[Sample] = []
    for s in iter_datasetv1_samples(dataset_dir):
        if args.require_html and s.html_path is None:
            continue
        (phishing if s.label == 1 else benign).append(s)

    if not benign or not phishing:
        raise SystemExit(
            f"Not enough samples. benign={len(benign)}, phishing={len(phishing)}"
        )

    rng = random.Random(args.seed)
    rng.shuffle(benign)
    rng.shuffle(phishing)

    selected: list[Sample]
    if args.mode == "balanced":
        n = min(len(benign), len(phishing))
        if args.limit_per_class and args.limit_per_class > 0:
            n = min(n, args.limit_per_class)

        benign = benign[:n]
        phishing = phishing[:n]

        # Interleave to avoid class blocks in index ordering
        selected = []
        for i in range(n):
            selected.append(benign[i])
            selected.append(phishing[i])
    else:
        if args.limit_per_class and args.limit_per_class > 0:
            benign = benign[: args.limit_per_class]
            phishing = phishing[: args.limit_per_class]
        selected = benign + phishing
        rng.shuffle(selected)

    index_csv = output_dir / "index.csv"
    with index_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "file_id",
                "label",
                "original_url",
                "dataset_sample_dir",
                "html_present",
            ],
        )
        writer.writeheader()

        per_label_index = {0: 0, 1: 0}
        for sample in selected:
            label = sample.label
            idx = per_label_index[label]
            per_label_index[label] += 1
            file_id = f"{label}_{idx}"

            # Screenshot
            shutil.copy2(sample.screenshot_path, out_images / f"{file_id}.png")

            # HTML + text (if available)
            html_present = False
            if sample.html_path is not None:
                html_present = True
                html_bytes = sample.html_path.read_bytes()
                (out_html / f"{file_id}.html").write_bytes(html_bytes)
                try:
                    html_str = html_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    html_str = html_bytes.decode("utf-8", errors="replace")
                text = html_to_visible_text(html_str)
                (out_text / f"{file_id}.txt").write_text(text, encoding="utf-8")
            else:
                # Still create an empty placeholder so downstream code doesn't break.
                (out_text / f"{file_id}.txt").write_text("", encoding="utf-8")

            writer.writerow(
                {
                    "file_id": file_id,
                    "label": label,
                    "original_url": sample.original_url or "",
                    "dataset_sample_dir": str(sample.sample_dir).replace("\\", "/"),
                    "html_present": int(html_present),
                }
            )

    print(
        f"Done. Mode={args.mode}. Output: {output_dir} "
        f"(html={len(list(out_html.glob('*.html')))}, images={len(list(out_images.glob('*.png')))}, text={len(list(out_text.glob('*.txt')))})"
    )
    print(f"Index: {index_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

