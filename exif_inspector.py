#!/usr/bin/env python3
"""
EXIF Inspector — simple, offline metadata extractor

Features
- Works on single files or directories (optionally recursive)
- Extracts EXIF for images via Pillow (PIL)
- Captures filesystem metadata (size, created/modified times)
- Optional SHA-256 hashing for integrity/triage
- Outputs to CSV and/or JSON; also prints a concise console table

Usage
  # Inspect a single file and print results
  python exif_inspector.py ./photo.jpg

  # Inspect a folder recursively, write CSV + JSON
  python exif_inspector.py ./samples -r --csv report.csv --json report.json

  # Add SHA-256 hashes (slower, but useful)
  python exif_inspector.py ./samples -r --hash --csv hashes.csv

Install
  pip install -r requirements.txt

Notes
- EXIF extraction requires image files supported by Pillow (e.g., JPEG, TIFF, some PNGs).
- HEIC/HEIF support may require extra libs and Pillow build options and is not guaranteed.
- Non-image files will still get filesystem metadata (size, times, hash if requested).

Author
  Prepared for Justin as a lightweight, shareable GitHub utility.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Dict, List, Iterable, Optional

try:
    from PIL import Image, ExifTags
except Exception as e:
    Image = None
    ExifTags = None

# --- Helpers -----------------------------------------------------------------

def fmt_ts(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts).isoformat(timespec="seconds")
    except Exception:
        return None

def sha256_file(path: str, bufsize: int = 1 << 20) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                b = f.read(bufsize)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()
    except Exception:
        return None

def try_open_image(path: str):
    if Image is None:
        return None
    try:
        img = Image.open(path)
        # Load to ensure headers parsed
        img.verify()  # type: ignore
        # Reopen for exif (verify() closes file)
        img = Image.open(path)
        return img
    except Exception:
        return None

def extract_exif(path: str) -> Dict[str, str]:
    """Return EXIF as a flat dict with human-readable keys where possible."""
    exif: Dict[str, str] = {}
    img = try_open_image(path)
    if img is None:
        return exif

    try:
        raw = getattr(img, "_getexif", lambda: None)()
        if not raw:
            # Some formats expose exif via getexif()
            raw = getattr(img, "getexif", lambda: {})()
        if not raw:
            return exif

        tag_map = {}
        if ExifTags and hasattr(ExifTags, "TAGS"):
            tag_map = ExifTags.TAGS

        # raw can be dict-like Exif object
        for k, v in dict(raw).items():
            key = tag_map.get(k, f"TAG_{k}")
            # Normalize simple types for JSON/CSV
            try:
                if isinstance(v, bytes):
                    v = v.decode("utf-8", errors="replace")
                elif isinstance(v, (list, tuple)):
                    v = ", ".join(map(str, v))
                exif[str(key)] = str(v)
            except Exception:
                exif[str(key)] = repr(v)
    except Exception:
        # Best-effort; swallow EXIF parse errors
        pass
    finally:
        try:
            img.close()
        except Exception:
            pass
    return exif

# --- Data Model ---------------------------------------------------------------

@dataclass
class Record:
    path: str
    name: str
    ext: str
    size_bytes: Optional[int] = None
    ctime: Optional[str] = None
    mtime: Optional[str] = None
    sha256: Optional[str] = None
    is_image: bool = False
    exif: Dict[str, str] = field(default_factory=dict)

    def flat(self) -> Dict[str, str]:
        """Flatten for CSV: top-level fields + selected EXIF keys expanded."""
        base = {
            "path": self.path,
            "name": self.name,
            "ext": self.ext,
            "size_bytes": self.size_bytes if self.size_bytes is not None else "",
            "ctime": self.ctime or "",
            "mtime": self.mtime or "",
            "sha256": self.sha256 or "",
            "is_image": str(self.is_image),
        }
        # Add EXIF keys; prefix to avoid collisions
        for k, v in self.exif.items():
            base[f"exif.{k}"] = v
        return base

# --- Core ---------------------------------------------------------------------

def gather_record(path: str, do_hash: bool = False) -> Record:
    st = None
    try:
        st = os.stat(path, follow_symlinks=False)
    except Exception:
        pass

    size = st.st_size if st else None
    ctime = fmt_ts(st.st_ctime) if st else None
    mtime = fmt_ts(st.st_mtime) if st else None

    img = try_open_image(path)
    is_img = img is not None
    if img is not None:
        try:
            img.close()
        except Exception:
            pass

    exif = extract_exif(path) if is_img else {}

    digest = sha256_file(path) if do_hash else None

    return Record(
        path=os.path.abspath(path),
        name=os.path.basename(path),
        ext=os.path.splitext(path)[1].lower().lstrip("."),
        size_bytes=size,
        ctime=ctime,
        mtime=mtime,
        sha256=digest,
        is_image=is_img,
        exif=exif,
    )

def iter_files(root: str, recursive: bool, follow_symlinks: bool, allow_exts: Optional[List[str]]) -> Iterable[str]:
    root = os.path.abspath(root)
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if allow_exts:
                ext = os.path.splitext(p)[1].lower().lstrip(".")
                if ext not in allow_exts:
                    continue
            yield p
        if not recursive:
            break

def print_table(records: List[Record], max_rows: int = 20):
    # Minimal console view (path, is_image, size, mtime, some EXIF highlights)
    cols = ["path", "is_image", "size_bytes", "mtime", "exif.DateTimeOriginal", "exif.Model", "exif.Make"]
    rows = []
    for r in records[:max_rows]:
        flat = r.flat()
        rows.append([
            flat.get("path", ""),
            flat.get("is_image", ""),
            flat.get("size_bytes", ""),
            flat.get("mtime", ""),
            flat.get("exif.DateTimeOriginal", ""),
            flat.get("exif.Model", ""),
            flat.get("exif.Make", ""),
        ])
    # Pretty print without external deps
    widths = [max(len(str(x)) for x in col) for col in zip(cols, *rows)] if rows else [len(c) for c in cols]
    def fmt_row(row):
        return " | ".join(str(val).ljust(w) for val, w in zip(row, widths))
    print(fmt_row(cols))
    print("-+-".join("-" * w for w in widths))
    for row in rows:
        print(fmt_row(row))
    if len(records) > max_rows:
        print(f"... ({len(records) - max_rows} more rows)")


def write_csv(path: str, records: List[Record]):
    # Compute union of keys for header
    fieldnames = set()
    flats = []
    for r in records:
        f = r.flat()
        flats.append(f)
        fieldnames.update(f.keys())
    fieldnames = sorted(fieldnames)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in flats:
            w.writerow(row)

def write_json(path: str, records: List[Record]):
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in records], f, ensure_ascii=False, indent=2)

# --- CLI ----------------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Simple, offline EXIF / metadata extractor.")
    p.add_argument("path", help="File or directory to inspect")
    p.add_argument("-r", "--recursive", action="store_true", help="Recurse into subdirectories")
    p.add_argument("--csv", help="Write results to CSV at this path")
    p.add_argument("--json", help="Write results to JSON at this path")
    p.add_argument("--hash", action="store_true", help="Compute SHA-256 for each file")
    p.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks when walking directories")
    p.add_argument("--filter-ext", help="Comma-separated list of file extensions to include (e.g. 'jpg,jpeg,png,tiff')")
    p.add_argument("--quiet", action="store_true", help="Do not print console table")
    return p.parse_args(argv)

def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    target = args.path

    if not os.path.exists(target):
        print(f"[!] Path not found: {target}", file=sys.stderr)
        return 2

    allow_exts = None
    if args.filter_ext:
        allow_exts = [e.strip().lower().lstrip(".") for e in args.filter_ext.split(",") if e.strip()]

    records: List[Record] = []
    for fp in iter_files(target, recursive=args.recursive, follow_symlinks=args.follow_symlinks, allow_exts=allow_exts):
        try:
            records.append(gather_record(fp, do_hash=args.hash))
        except KeyboardInterrupt:
            print("[!] Interrupted.", file=sys.stderr)
            return 130
        except Exception as e:
            print(f"[!] Error processing {fp}: {e}", file=sys.stderr)

    if not args.quiet:
        print_table(records)

    if args.csv:
        write_csv(args.csv, records)
        print(f"[+] Wrote CSV: {args.csv}")
    if args.json:
        write_json(args.json, records)
        print(f"[+] Wrote JSON: {args.json}")

    # Helpful exit code: 0 even if some files failed, 1 if nothing processed
    if len(records) == 0:
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
