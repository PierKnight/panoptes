from pathlib import Path
from typeguard import typechecked

@typechecked
class Workspace:
    """
    Convenience helper that knows where to put files for a given investigation.
    It creates a directory structure based on the domain and services involved in the investigation.
    The directory structure is as follows:
    ```
    workspace/
    └── <domain>
        ├── <service1>
        │   └── <filename>
        ├── <service2>
        │   └── <filename>
        └── ...
    ```
    The `Workspace` class provides methods to create directories for services, get the directory for a specific service,
    and create or retrieve files within those service directories. It also includes a method to clean up empty directories.
    """

    def __init__(self, root: Path, domain: str, services: list[str]):
        self.root = root / domain
        self.root.mkdir(parents=True, exist_ok=True)
        for s in services:
            (self.root / s).mkdir(exist_ok=True)

    def service_dir(self, service: str) -> Path:
        return self.root / service

    def file(self, service: str, filename: str) -> Path:
        p = self.root / service / filename
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
    
    def cleanup_empty_dirs(self):
        """
        Remove empty directories in the workspace.
        """
        for service_dir in self.root.iterdir():
            if service_dir.is_dir() and not any(service_dir.iterdir()):
                service_dir.rmdir()
        if not any(self.root.iterdir()):
            self.root.rmdir()