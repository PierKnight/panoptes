from __future__ import annotations
import uuid

def _uuid() -> str:          # helper so id defaults are unique
    return str(uuid.uuid4())

## To be filled