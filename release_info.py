from pathlib import Path


APP_CODE_NAME = "AutoShopee"
APP_DISPLAY_NAME = "Auto-Shopee"
APP_VERSION = "2.1.0"
APP_BUILD_LABEL = f"version {APP_VERSION}"
APP_BUNDLE_NAME = f"{APP_CODE_NAME}_v{APP_VERSION}"
BUILD_OUTPUT_ROOT = Path("build-final")
BACKEND_EXPORT_REPO = "Backend-Shopee-Software"


def build_output_dir() -> Path:
    return BUILD_OUTPUT_ROOT / APP_BUILD_LABEL


def backend_export_dir() -> Path:
    return BUILD_OUTPUT_ROOT / APP_BUILD_LABEL / BACKEND_EXPORT_REPO
