from __future__ import annotations

import importlib
import os
import shutil
import site
import sys
from functools import lru_cache
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[2]
KNOWN_VENDOR_DIRS = [
    Path(os.getenv("TRUECORE_VENDOR_PATH", "")).expanduser() if os.getenv("TRUECORE_VENDOR_PATH") else None,
    ROOT_DIR / "vendor_py",
    Path(r"C:\tc_vendor"),
]
KNOWN_TESSERACT_PATHS = [
    Path(r"C:\Program Files\PDF24\tesseract\tesseract.exe"),
    Path(r"C:\Program Files\Tesseract-OCR\tesseract.exe"),
]
KNOWN_TESSDATA_DIRS = [
    Path(os.getenv("LOCALAPPDATA", "")) / "TrueCoreOCR" / "tessdata" if os.getenv("LOCALAPPDATA") else None,
    Path(r"C:\Program Files\PDF24\tesseract\tessdata"),
    Path(r"C:\Program Files\Tesseract-OCR\tessdata"),
]


def normalize_existing_path(path_like) -> Path | None:
    if not path_like:
        return None

    try:
        path = Path(path_like).expanduser()
    except Exception:
        return None

    return path if path.exists() else None


def resolve_user_scripts_dir() -> Path | None:
    try:
        user_site = Path(site.getusersitepackages())
    except Exception:
        return None

    if not user_site.exists():
        return None

    scripts_dir = user_site.parent / "Scripts"
    return scripts_dir if scripts_dir.exists() else None


def resolve_winget_poppler_bin_dir() -> Path | None:
    packages_root = Path.home() / "AppData" / "Local" / "Microsoft" / "WinGet" / "Packages"
    if not packages_root.exists():
        return None

    for candidate in sorted(packages_root.glob("oschwartz10612.Poppler_*"), reverse=True):
        bin_dir = candidate / next(iter(sorted(candidate.glob("poppler-*"))), Path()) / "Library" / "bin"
        if bin_dir.exists():
            return bin_dir

    return None


def resolve_ghostscript_bin_dir() -> Path | None:
    roots = [
        Path(r"C:\Program Files\gs"),
        Path(r"C:\Program Files (x86)\gs"),
        Path(r"C:\Program Files\PDF24\gs"),
    ]

    candidates = []
    for root in roots:
        if not root.exists():
            continue
        if (root / "bin").exists():
            candidates.append(root / "bin")
        for entry in root.glob("gs*"):
            bin_dir = entry / "bin"
            if bin_dir.exists():
                candidates.append(bin_dir)

    if not candidates:
        return None

    return sorted(candidates, reverse=True)[0]


def resolve_tessdata_dir() -> Path | None:
    for candidate in KNOWN_TESSDATA_DIRS:
        path = normalize_existing_path(candidate)
        if path is None:
            continue
        if (path / "eng.traineddata").exists():
            return path

    return None


def iter_vendor_dirs():
    for candidate in KNOWN_VENDOR_DIRS:
        path = normalize_existing_path(candidate)
        if path is not None:
            yield path


def ensure_vendor_paths(front: bool = False) -> list[str]:
    inserted = []
    vendor_paths = [str(path) for path in iter_vendor_dirs()]
    if front:
        vendor_paths = list(reversed(vendor_paths))

    for path in vendor_paths:
        if path in sys.path:
            continue
        if front:
            sys.path.insert(0, path)
        else:
            sys.path.append(path)
        inserted.append(path)

    return inserted


def import_optional_module(module_name: str, *, use_vendor: bool = False):
    if use_vendor:
        ensure_vendor_paths(front=True)

    try:
        return importlib.import_module(module_name)
    except Exception:
        return None


@lru_cache(maxsize=16)
def module_available(module_name: str, use_vendor: bool = False) -> bool:
    return import_optional_module(module_name, use_vendor=use_vendor) is not None


def resolve_executable(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found

    lower_name = name.lower()
    if lower_name == "tesseract":
        for candidate in KNOWN_TESSERACT_PATHS:
            existing = normalize_existing_path(candidate)
            if existing is not None:
                return str(existing)

    if lower_name in {"ocrmypdf", "easyocr"}:
        scripts_dir = resolve_user_scripts_dir()
        if scripts_dir is not None:
            candidate = scripts_dir / f"{name}.exe"
            if candidate.exists():
                return str(candidate)

    if lower_name in {"pdftotext", "pdftoppm", "pdfinfo", "pdftocairo"}:
        poppler_bin = resolve_winget_poppler_bin_dir()
        if poppler_bin is not None:
            candidate = poppler_bin / f"{name}.exe"
            if candidate.exists():
                return str(candidate)

    if lower_name == "gswin64c":
        ghostscript_bin = resolve_ghostscript_bin_dir()
        if ghostscript_bin is not None:
            candidate = ghostscript_bin / "gswin64c.exe"
            if candidate.exists():
                return str(candidate)

    return None


def build_execution_env(extra_paths: list[str] | None = None) -> dict:
    env = os.environ.copy()
    path_entries = []

    for entry in extra_paths or []:
        path = normalize_existing_path(entry)
        if path is not None:
            path_entries.append(str(path))

    scripts_dir = resolve_user_scripts_dir()
    if scripts_dir is not None:
        path_entries.append(str(scripts_dir))

    poppler_bin = resolve_winget_poppler_bin_dir()
    if poppler_bin is not None:
        path_entries.append(str(poppler_bin))

    ghostscript_bin = resolve_ghostscript_bin_dir()
    if ghostscript_bin is not None:
        path_entries.append(str(ghostscript_bin))

    tesseract_path = resolve_executable("tesseract")
    if tesseract_path:
        path_entries.append(str(Path(tesseract_path).parent))
        env.setdefault("TESSERACT_EXE", tesseract_path)

    tessdata_dir = resolve_tessdata_dir()
    if tessdata_dir is not None:
        env.setdefault("TESSDATA_PREFIX", str(tessdata_dir))

    if path_entries:
        existing_path = env.get("PATH", "")
        unique_entries = []
        seen = set()
        for entry in path_entries:
            normalized = os.path.normcase(entry)
            if normalized in seen:
                continue
            seen.add(normalized)
            unique_entries.append(entry)
        env["PATH"] = os.pathsep.join(unique_entries + [existing_path])

    return env


def configure_tesseract(pytesseract_module) -> str | None:
    tesseract_path = resolve_executable("tesseract")
    if not tesseract_path or pytesseract_module is None:
        return None

    try:
        pytesseract_module.pytesseract.tesseract_cmd = tesseract_path
        tessdata_dir = resolve_tessdata_dir()
        if tessdata_dir is not None:
            os.environ.setdefault("TESSDATA_PREFIX", str(tessdata_dir))
    except Exception:
        return None

    return tesseract_path


@lru_cache(maxsize=1)
def get_rapidocr_engine():
    module = import_optional_module("rapidocr_onnxruntime")
    if module is None:
        return None

    try:
        return module.RapidOCR()
    except Exception:
        return None


@lru_cache(maxsize=1)
def get_easyocr_reader():
    module = import_optional_module("easyocr")
    if module is None:
        return None

    try:
        return module.Reader(["en"], gpu=False, download_enabled=True, verbose=False)
    except Exception:
        return None


def heavy_ocr_enabled() -> bool:
    return str(os.getenv("TRUECORE_ENABLE_HEAVY_OCR", "")).strip().lower() in {"1", "true", "yes", "on"}


@lru_cache(maxsize=1)
def get_doctr_predictor():
    ensure_vendor_paths(front=True)
    try:
        from doctr.models import ocr_predictor
    except Exception:
        return None

    try:
        return ocr_predictor(pretrained=True)
    except Exception:
        return None


@lru_cache(maxsize=1)
def get_paddleocr_engine():
    if not heavy_ocr_enabled():
        return None

    ensure_vendor_paths(front=True)
    os.environ.setdefault("PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK", "True")
    module = import_optional_module("paddleocr", use_vendor=True)
    if module is None:
        return None

    try:
        return module.PaddleOCR(
            use_doc_orientation_classify=False,
            use_doc_unwarping=False,
            use_textline_orientation=False,
            lang="en",
        )
    except Exception:
        return None


def available_ocr_providers() -> list[str]:
    providers = []
    if module_available("rapidocr_onnxruntime"):
        providers.append("rapidocr")
    if resolve_executable("tesseract"):
        providers.append("tesseract_layout")
    if module_available("easyocr"):
        providers.append("easyocr")
    if module_available("doctr", use_vendor=True):
        providers.append("doctr")
    if heavy_ocr_enabled() and module_available("paddleocr", use_vendor=True):
        providers.append("paddleocr")
    return providers


def available_pdf_tools() -> list[str]:
    tools = []
    if resolve_executable("pdftotext"):
        tools.append("pdftotext")
    if resolve_executable("pdftoppm"):
        tools.append("pdftoppm")
    if resolve_executable("tesseract"):
        tools.append("tesseract")
    if resolve_executable("ocrmypdf"):
        tools.append("ocrmypdf")
    if resolve_executable("gswin64c"):
        tools.append("ghostscript")
    return tools


def ocrmypdf_available() -> bool:
    return bool(resolve_executable("ocrmypdf") and resolve_executable("tesseract") and resolve_executable("gswin64c"))


__all__ = [
    "available_ocr_providers",
    "available_pdf_tools",
    "build_execution_env",
    "configure_tesseract",
    "ensure_vendor_paths",
    "get_doctr_predictor",
    "get_easyocr_reader",
    "get_paddleocr_engine",
    "get_rapidocr_engine",
    "heavy_ocr_enabled",
    "import_optional_module",
    "module_available",
    "ocrmypdf_available",
    "resolve_executable",
    "resolve_ghostscript_bin_dir",
    "resolve_tessdata_dir",
    "resolve_user_scripts_dir",
    "resolve_winget_poppler_bin_dir",
]
