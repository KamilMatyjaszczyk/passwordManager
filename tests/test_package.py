import tomllib
from pathlib import Path

from manager import __version__


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_project_version_comes_from_manager_package() -> None:
    projectConfig = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert projectConfig["project"]["dynamic"] == ["version"]
    assert projectConfig["project"]["readme"] == "README.md"
    assert (
        projectConfig["tool"]["setuptools"]["dynamic"]["version"]["attr"]
        == "manager.__version__"
    )
    assert __version__ == "0.1.0"


def test_pm_command_delegates_to_cli_main() -> None:
    projectConfig = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert projectConfig["project"]["scripts"] == {
        "pm": "manager.cli:main",
    }
