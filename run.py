#!/usr/bin/env python3
"""One-click launcher: installs missing packages, trains the models if needed, opens the dashboard.

    python run.py                # train if needed, start dashboard, open browser
    python run.py --retrain      # force a fresh run of the whole pipeline
    python run.py --regen        # also regenerate the synthetic corpus
    python run.py --no-browser   # start the server without opening a browser
    python run.py --port 9000
"""
import importlib
import os
import socket
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

NEEDED = {"numpy": "numpy", "pandas": "pandas", "scipy": "scipy", "sklearn": "scikit-learn", "joblib": "joblib"}


def ensure_deps():
    missing = []
    for mod, pkg in NEEDED.items():
        try:
            importlib.import_module(mod)
        except ImportError:
            missing.append(pkg)
    if missing:
        print("Installing missing packages:", ", ".join(missing), flush=True)
        cmd = [sys.executable, "-m", "pip", "install", *missing]
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError:
            subprocess.check_call(cmd + ["--break-system-packages"])


def free_port(start):
    for p in range(start, start + 30):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", p)) != 0:
                return p
    return start


def main():
    if sys.version_info < (3, 9):
        sys.exit("Python 3.9 or newer is required.")
    args = sys.argv[1:]
    ensure_deps()
    from src import config, pipeline, server
    port = 8765
    if "--port" in args:
        port = int(args[args.index("--port") + 1])
    model_file = os.path.join(config.MODELS, f"phishshift_model_{config.MODEL_VERSION}.joblib")
    summary_file = os.path.join(config.OUTPUTS, "summary.json")
    if "--retrain" in args or "--regen" in args or not (os.path.exists(model_file) and os.path.exists(summary_file)):
        print("Training models (about 10-30 seconds) ...", flush=True)
        pipeline.run(force_regen="--regen" in args)
    server.serve(free_port(port), open_browser="--no-browser" not in args)


if __name__ == "__main__":
    main()
