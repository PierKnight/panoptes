from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid

def _uuid() -> str:          # helper so id defaults are unique
    return str(uuid.uuid4())

@dataclass
class Client:
    id: str = field(default_factory=_uuid)
    name: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class Investigation:
    id: str = field(default_factory=_uuid)
    client_id: str = ""
    started_at: datetime = field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
    status: str = "NEW"       # NEW / SUCCESS / FAILED

@dataclass
class Artifact:
    id: str = field(default_factory=_uuid)
    investigation_id: str = ""
    service: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class Report:
    id: str = field(default_factory=_uuid)
    investigation_id: str = ""
    markdown: str = ""
    pdf_path: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)