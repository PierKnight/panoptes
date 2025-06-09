from pathlib import Path
import os, yaml

def load() -> dict:
    with open(Path.home()/".osintapp.yml") as f:
        cfg = yaml.safe_load(f)
    # env-override
    for k,v in cfg["api_keys"].items():
        cfg["api_keys"][k] = os.getenv(k.upper(), v)
    return cfg