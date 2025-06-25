# Import necessary libraries
from pathlib import Path
import json
import subprocess
from datetime import datetime
from importlib import metadata
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

# Import project-specific utilities
from panoptes.utils import logging
from panoptes.ingestion.imgbb import ImgBB
from ..utils.misc import get_field_name_from_service_dir_name

# Initialize logger for this module
log = logging.get(__name__)

# Get package version (currently unused)
PKG_VERSION = metadata.version("panoptes")

@dataclass
class ReportContext:
    """Data structure for storing all report information."""
    # Basic domain information
    domain: str  # The domain being analyzed
    run_datetime: str  # When the report was generated
    git_sha: str  # Git commit SHA for version tracking
    is_incremental: bool = False  # Whether this is an incremental report
    
    # Various security analysis fields with empty defaults
    header_analysis: Dict[str, Any] = field(default_factory=dict)
    dmarc: List[Dict[str, Any]] = field(default_factory=list)  # DMARC records
    spf: List[Dict[str, Any]] = field(default_factory=list)  # SPF records
    dns_records: Dict[str, Any] = field(default_factory=dict)  # DNS information
    ssl_check: Dict[str, Any] = field(default_factory=dict)  # SSL certificate checks
    tech_stack: Dict[str, Any] = field(default_factory=dict)  # Detected technologies
    subdomains_ips: Dict[str, Any] = field(default_factory=dict)  # Subdomain/IP mappings
    hosts: Dict[str, Any] = field(default_factory=dict)  # Host information
    compromised_ips: Dict[str, Any] = field(default_factory=dict)  # Known bad IPs
    leaked_credentials: Dict[str, Any] = field(default_factory=dict)  # Credential leaks
    data_breaches: Dict[str, Any] = field(default_factory=dict)  # Breach information
    images: Dict[str, Any] = field(default_factory=dict)  # Uploaded analysis images

    def to_dict(self) -> Dict[str, Any]:
        """Convert the dataclass to a dictionary"""
        data = self.__dict__.copy()
        return {k: v for k, v in data.items() if v}  # Filter out empty fields

class ReportBuilder:
    """Builds security assessment reports from collected workspace data."""
    
    def __init__(self, imgbb_api_key: Optional[str] = None, is_incremental: bool = False):
        # Initialize image uploader if API key provided
        self.imgbb = ImgBB(imgbb_api_key) if imgbb_api_key else None
        self.is_incremental = is_incremental  # Track if this is an incremental report
        if not imgbb_api_key:
            log.warning("No ImgBB API key provided, images will not be uploaded.")
    
    def get_git_sha(self) -> str:
        """Get the short git commit hash for the current code version."""
        try:
            return subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"], 
                text=True
            ).strip()
        except subprocess.CalledProcessError:
            log.warning("Failed to get git SHA")
            return "unknown"  # Fallback value

    def process_json_files(self, service_dir: Path, field_name: str, ctx: ReportContext) -> None:
        """
        Process all JSON files in a service directory.
        Handles special cases for MXToolbox and DNSDumpster formats.
        """
        for json_file in service_dir.glob("*.json"):
            if field_name == "mxtoolbox":
                self._process_mxtoolbox_json(json_file, ctx)
            elif field_name == "dns_records":
                self._process_dnsdumpster_json(json_file, ctx)
            else:
                try:
                    # For generic JSON files, load and assign to the context field
                    setattr(ctx, field_name, json.loads(json_file.read_text()))
                except (json.JSONDecodeError, IOError) as e:
                    log.error(f"Failed to process {json_file}: {e}")
    
    def _process_dnsdumpster_json(self, json_file: Path, ctx: ReportContext) -> None:
        """Process DNSDumpster JSON files, extracting domain from filename."""
        try:
            # Filename format: dns_records_example.com.json
            domain = json_file.name.split("_")[2].replace(".json", "")
            data = json.loads(json_file.read_text())
            ctx.dns_records[domain] = data  # Store under domain key
        except (json.JSONDecodeError, IOError, IndexError) as e:
            log.error(f"Failed to process DNSDumpster file {json_file}: {e}")

    def _process_mxtoolbox_json(self, json_file: Path, ctx: ReportContext) -> None:
        """Process MXToolbox JSON files, separating DMARC and SPF records."""
        try:
            data = json.loads(json_file.read_text())
            if json_file.name.startswith("dmarc"):
                ctx.dmarc.append(data)  # Add to DMARC list
            elif json_file.name.startswith("spf"):
                ctx.spf.append(data)  # Add to SPF list
        except (json.JSONDecodeError, IOError) as e:
            log.error(f"Failed to process MXToolbox file {json_file}: {e}")
    
    def process_images(self, service_dir: Path, ctx: ReportContext) -> None:
        """Handle image processing for services that generate visual reports."""
        if not self.imgbb:  # Skip if no image uploader configured
            return
        
        # Route to appropriate image processor
        if service_dir.name == "mxtoolbox":
            self._process_mxtoolbox_images(service_dir, ctx)
        elif service_dir.name == "sslshopper":
            self._process_sslshopper_images(service_dir, ctx)
    
    def _process_mxtoolbox_images(self, service_dir: Path, ctx: ReportContext) -> None:
        """Upload MXToolbox DMARC/SPF report images to ImgBB."""
        # Initialize image storage structure
        ctx.images["spf"] = {}
        ctx.images["dmarc"] = {}
        
        for image_file in service_dir.glob("*.png"):
            try:
                # Determine if this is DMARC or SPF image
                if image_file.name.startswith("dmarc"):
                    image_type = "dmarc"
                elif image_file.name.startswith("spf"):
                    image_type = "spf"
                else:
                    continue  # Skip non-relevant images
                
                # Extract domain from filename (dmarc_example.com.png)
                domain = image_file.name.split("_")[1].replace(".png", "")
                # Upload image and store URL
                image_url = self.imgbb.upload_image(str(image_file), name=image_file.name)
                ctx.images[image_type][domain] = image_url
                
            except (IndexError, Exception) as e:
                log.error(f"Failed to process image {image_file}: {e}")
    
    def _process_sslshopper_images(self, service_dir: Path, ctx: ReportContext) -> None:
        """Process SSL certificate check images from SSLShopper."""
        for image_file in service_dir.glob("*.png"):
            try:
                # Upload first found image as the SSL check result
                ctx.images["ssl_check"] = self.imgbb.upload_image(str(image_file))
                break  # Only need one image
            except Exception as e:
                log.error(f"Failed to process SSLShopper image {image_file}: {e}")
    
    def build(self, workspace: Path) -> Dict[str, Any]:
        """Main method to build report from workspace directory."""
        # Initialize context with basic info
        ctx = ReportContext(
            domain=workspace.name,
            run_datetime=str(datetime.now()),
            git_sha=self.get_git_sha(),
            is_incremental=self.is_incremental
        )
        
        # Process each service directory
        for service_dir in workspace.iterdir():
            if not service_dir.is_dir():
                continue
            
            # Get corresponding field name for this service
            field_name = get_field_name_from_service_dir_name(service_dir.name)
            
            # Process all JSON files in directory
            self.process_json_files(service_dir, field_name, ctx)
                
            # Special handling for services with images
            if service_dir.name in ["mxtoolbox", "sslshopper"]:
                self.process_images(service_dir, ctx)
        
        # Return as clean dictionary
        return ctx.to_dict()

# Module-level convenience function
def build(workspace: Path, **kwargs) -> Dict[str, Any]:
    """
    Public interface for building reports.
    Args:
        workspace: Directory containing analysis results
        **kwargs: Additional options (e.g., imgbb_api_key)
    Returns:
        Complete report dictionary
    """
    builder = ReportBuilder(**kwargs)
    return builder.build(workspace)