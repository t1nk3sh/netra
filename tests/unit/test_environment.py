import shutil
import subprocess
import sys


def test_python_version():
    major, minor = sys.version_info[:2]
    assert major == 3
    assert minor >= 12, f"Python 3.12+ required, got 3.{minor}"


def test_pip_packages():
    required = [
        "pandas",
        "numpy",
        "scipy",
        "sklearn",
        "xgboost",
        "joblib",
        "pydantic",
        "fastapi",
        "uvicorn",
        "sqlalchemy",
        "psycopg",
        "yaml",
        "pytest",
        "scapy",
    ]
    for pkg in required:
        __import__(pkg)


def test_tcpdump_available():
    assert shutil.which("tcpdump"), "tcpdump not found on PATH"


def test_node_available():
    result = subprocess.run(["node", "--version"], capture_output=True, text=True)
    assert result.returncode == 0
    version = result.stdout.strip()
    assert version.startswith("v"), f"Unexpected node version: {version}"


def test_npm_available():
    result = subprocess.run(["npm", "--version"], capture_output=True, text=True)
    assert result.returncode == 0


def test_docker_available():
    result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
    assert result.returncode == 0


def test_git_available():
    assert shutil.which("git"), "git not found on PATH"
