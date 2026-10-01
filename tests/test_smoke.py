import subprocess
import sys


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "main.py", *args], capture_output=True, text=True)


def test_runs_without_args():
    res = run()
    assert res.returncode == 0


def test_handles_bad_input():
    res = run("--definitely-not-a-valid-flag")
    assert res.returncode in (0, 2)
