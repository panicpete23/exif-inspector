# EXIF Inspector

[![CI](https://github.com/panicpete23/exif-inspector/actions/workflows/ci.yml/badge.svg)](https://github.com/panicpete23/exif-inspector/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)

A lightweight, **offline** EXIF and file metadata extractor written in Python. Ideal for blue-team triage, DFIR notes, or quick inventorying of image collections.

## Features
- Works on a single file or an entire directory (with `-r` for recursion)
- Extracts EXIF for images using Pillow (where available)
- Records filesystem metadata: size, created/modified timestamps
- Optional **SHA-256** hashing for integrity checks (`--hash`)
- Export to **CSV** and/or **JSON**
- Minimal console table for a quick glance

## Install
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage
Inspect a single file and print a quick view:
```bash
python exif_inspector.py ./photo.jpg
```

Walk a folder recursively and save outputs:
```bash
python exif_inspector.py ./samples -r --csv report.csv --json report.json
```

Include SHA-256 hashing (slower):
```bash
python exif_inspector.py ./samples -r --hash --csv hashes.csv
```

Filter by extensions (example: only JPEG and PNG):
```bash
python exif_inspector.py ./samples -r --filter-ext jpg,jpeg,png
```

## Notes
- EXIF availability depends on the file and Pillow support. JPEG/TIFF are safest. Some PNGs may include textual metadata; HEIC/HEIF support varies.
- Non-image files still receive filesystem metadata and optional hash values.

## Why this project?
A simple, audit-friendly tool you can keep offline. Good for quick wins on your GitHub and genuinely useful for everyday investigations.

---

MIT License © 2025 Justin Cox

---

## Project Structure
```
exif-inspector/
├── exif_inspector.py        # Main script
├── requirements.txt         # Dependencies (Pillow)
├── README.md                # Project overview + usage
├── LICENSE                  # MIT license
├── .gitignore               # Git ignore rules
├── .github/
│   └── workflows/
│       └── ci.yml           # GitHub Actions workflow
└── samples/
    ├── sample.jpg           # Example image
    ├── report.csv           # Example CSV output
    └── report.json          # Example JSON output
```

## Disclaimer  
This is a **personal project** created for learning and community sharing.  
It is **not affiliated with, endorsed by, or representative of my employer(s)** past or present.  
All code is provided under the MIT License.