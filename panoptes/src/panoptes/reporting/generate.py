"""
Report generation module for creating HTML and PDF reports from collected data.
Handles both full and incremental report generation with language support.
"""

from pathlib import Path
import json
import datetime
from typeguard import typechecked
from jinja2 import Environment, FileSystemLoader
from panoptes.utils import logging
from panoptes.utils.console import console
from .context import build
from .pdf import html_to_pdf
from typing import Any


# Initialize logging
log = logging.get(__name__)

# Constants for template handling
TEMPLATE_DIR = Path(__file__).parent / "templates"
LANGUAGE_TEMPLATES = {
    "it": "report-it.html.j2",
    "en": "report-en.html.j2"
}

@typechecked
def write_report_json(workspace: Path, new_data: dict, **kwargs) -> Path:
    """Write the report data to a JSON file in the workspace.
    
    Args:
        workspace: Path to the workspace directory
        **kwargs: Additional arguments including imgbb_api_key
        
    Returns:
        Path to the generated JSON file
    """
    # Write new report
    json_path = workspace / "report.json"
    json_path.write_text(json.dumps(new_data, indent=2))
    return json_path

@typechecked
def _get_domain_from_workspace(workspace: Path) -> str:
    """Extract domain name from workspace path.
    
    Args:
        workspace: Path object containing the domain name
        
    Returns:
        Extracted domain string
    """
    return workspace.name.split(".")[-2]

@typechecked
def _setup_jinja_environment() -> Environment:
    """Configure and return Jinja2 template environment.
    
    Returns:
        Configured Jinja2 Environment instance
    """
    return Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=True,  # Automatic HTML escaping for security
    )

@typechecked
def _dict_diff(d1: Any, d2: Any) -> Any:
    """
    Recursively computes the difference between two dictionaries.
    Returns a dict with keys from d1 whose values are missing or different in d2.
    Handles nested dicts and lists of basic types or dicts.
    """
    if isinstance(d1, dict) and isinstance(d2, dict):
        diff = {}
        if "domain" in d1:
            # We always include the domain in the diff
            diff["domain"] = d1["domain"]
        for key in d1:
            if key not in d2:
                diff[key] = d1[key]
            else:
                nested_diff = _dict_diff(d1[key], d2[key])
                if nested_diff not in (None, {}, [], False):
                    diff[key] = nested_diff
        return diff

    elif isinstance(d1, list) and isinstance(d2, list):
        # Compare lists by content
        if all(isinstance(item, dict) for item in d1 + d2):
            # List of dicts: compare each item by index
            result = []
            for i in range(len(d1)):
                if i >= len(d2):
                    result.append(d1[i])  # Item missing in d2
                else:
                    item_diff = _dict_diff(d1[i], d2[i])
                    if item_diff not in (None, {}, [], False):
                        result.append(item_diff)
            return result if result else None
        else:
            # List of primitives (e.g., list of strings)
            return d1 if d1 != d2 else None

    else:
        # Base case: simple value comparison
        return d1 if d1 != d2 else None

@typechecked
def _dict_union(d1: Any, d2: Any) -> Any:
    """
    Recursively merges two dictionaries.
    - Prefers values from d1 when there's a conflict
    - Merges nested dicts
    - Deduplicates lists of dictionaries using unique identifiers
    """
    if isinstance(d1, dict) and isinstance(d2, dict):
        result = dict(d2)  # Start from d2 so d1 can override
        for key, val1 in d1.items():
            if key in result:
                val2 = result[key]
                result[key] = _dict_union(val1, val2)
            else:
                result[key] = val1
        return result

    elif isinstance(d1, list) and isinstance(d2, list):
        # Special handling for known deduplication fields
        if d1 and isinstance(d1[0], dict) and "name" in d1[0]:
            # Data breaches list - deduplicate by "name"
            merged = {item["name"]: item for item in d2}
            for item in d1:
                merged[item["name"]] = item
            return list(merged.values())
            
        elif d1 and isinstance(d1[0], dict) and "port" in d1[0]:
            # Exposed ports list - deduplicate by "port"
            merged = {item["port"]: item for item in d2}
            for item in d1:
                merged[item["port"]] = item
            return list(merged.values())
            
        # For other lists, use new values only
        return d1

    # For other types (str, int, etc.), prefer d1's value
    return d1

@typechecked
def generate_report(
    workspace: Path,
    incremental: bool = False,
    language: str = "en",
    export_from_html: bool = False,
    **kwargs
) -> tuple[Path, Path]:
    """Generate HTML and PDF reports from collected data.
    
    Args:
        workspace: Path to workspace directory with collected data
        incremental: Whether to generate incremental report
        language: Report language ('en' or 'it')
        export_from_html: Use existing HTML instead of generating new
        **kwargs: Additional arguments including imgbb_api_key
        
    Returns:
        Tuple of (html_path, pdf_path)
        
    Raises:
        FileNotFoundError: If workspace doesn't exist
    """
    # Validate workspace exists
    if not workspace.exists():
        log.error(f"Workspace {workspace} does not exist")
        raise FileNotFoundError(f"Workspace {workspace} not found")

    domain = _get_domain_from_workspace(workspace)
    html_path = workspace / f"osint-report-{domain}-{language}.html"
    pdf_path = workspace / f"osint-report-{domain}-{language}.pdf"
    report_json_path = workspace / "report.json"

    if not export_from_html:
        # Generate fresh HTML report
        env = _setup_jinja_environment()
        template = env.get_template(LANGUAGE_TEMPLATES[language])
        env.globals["ws"] = workspace  # Make workspace available in templates

        # Get current report data
        report_dict = build(workspace, imgbb_api_key=kwargs.get("imgbb_api_key"))

        merged_report = None
        incremental_data = None

        # If there is an existing report, merge it (so that we always have all data retrieved)
        if report_json_path.exists():
            log.info(f"Loading existing report data from {report_json_path}")

            # Load existing report data
            old_data = json.loads(report_json_path.read_text())

            # Handle incremental mode
            if incremental:          
                incremental_data = _dict_diff(report_dict, old_data)
                incremental_data["is_incremental"] = True
                diff = workspace/"report.diff.json"
                diff.write_text(json.dumps(incremental_data, indent=2)) 

            # Merge old data with new data
            merged_report = _dict_union(report_dict, old_data)
        else:
            if incremental:
                log.warning("No existing report found for incremental mode, generating full report instead.")
            merged_report = report_dict
        
        current_data = incremental_data if incremental_data else merged_report 

        if "is_incremental" in report_dict:
            del report_dict["is_incremental"]  # We don't need this in the json file

        write_report_json(workspace, report_dict, **kwargs)
        write_report_json(workspace, current_data, **kwargs)
                
        # Render template with current data
        with console.status("Rendering HTML from template..."):
            html = template.render(current_data)

        # Ensure workspace exists and write HTML
        workspace.mkdir(parents=True, exist_ok=True)
        html_path.write_text(html)
    else:
        # Use existing HTML file
        if not html_path.exists():
            log.error(f"HTML report {html_path} does not exist")
            raise FileNotFoundError(f"HTML report {html_path} not found")
        html = html_path.read_text()

    # Generate PDF from HTML
    with console.status("Generating PDF from HTML..."):
        html_to_pdf(html_content=html, output_path=pdf_path)

    return html_path, pdf_path