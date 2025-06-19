"""
Report generation module for creating HTML and PDF reports from collected data.
Handles both full and incremental report generation with language support.
"""

from pathlib import Path
import json
import datetime
from typeguard import typechecked
from jinja2 import Environment, FileSystemLoader
from deepdiff import DeepDiff
from panoptes.utils import logging
from panoptes.utils.console import console
from .context import build
from .pdf import html_to_pdf

# Initialize logging
log = logging.get(__name__)

# Constants for template handling
TEMPLATE_DIR = Path(__file__).parent / "templates"
LANGUAGE_TEMPLATES = {
    "it": "report-it.html.j2",
    "en": "report-en.html.j2"
}

@typechecked
def write_report_json(workspace: Path, **kwargs) -> Path:
    """Write the report data to a JSON file in the workspace.
    
    Args:
        workspace: Path to the workspace directory
        **kwargs: Additional arguments including imgbb_api_key
        
    Returns:
        Path to the generated JSON file
    """
    new_data = build(workspace, imgbb_api_key=kwargs.get("imgbb_api_key"))
    
    # Handle previous report if exists
    prev_report = workspace / "report.json"
    if prev_report.exists():
        prev_report.rename(workspace / "report.prev.json")
    
    # Write new report
    json_path = workspace / "report.json"
    json_path.write_text(json.dumps(new_data, indent=2))
    return json_path

def _get_domain_from_workspace(workspace: Path) -> str:
    """Extract domain name from workspace path.
    
    Args:
        workspace: Path object containing the domain name
        
    Returns:
        Extracted domain string
    """
    return workspace.name.split(".")[-2]

def _setup_jinja_environment() -> Environment:
    """Configure and return Jinja2 template environment.
    
    Returns:
        Configured Jinja2 Environment instance
    """
    return Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=True,  # Automatic HTML escaping for security
    )

def _generate_diff_report(current_data: dict, workspace: Path) -> dict:
    """Generate incremental diff report compared to previous run.
    
    Args:
        current_data: Current report data
        workspace: Workspace directory containing previous report
        
    Returns:
        Dictionary containing only changed data
    """
    prev_json_path = workspace / "report.prev.json"
    if not prev_json_path.exists():
        log.warning("No previous report found for incremental mode")
        return current_data

    previous_data = json.loads(prev_json_path.read_text())
    diff = DeepDiff(previous_data, current_data, ignore_order=True)
    
    # Create simplified diff structure
    diff_data = {}
    for key in diff.get('dictionary_item_added', []):
        clean_key = key.replace('root.', '')
        diff_data[clean_key] = current_data[clean_key]
    for key in diff.get('values_changed', []):
        clean_key = key.replace('root.', '')
        diff_data[clean_key] = current_data[clean_key]
    
    # Save diff for reference
    diff_path = workspace / "report.diff.json"
    diff_path.write_text(json.dumps(diff_data, indent=2))
    
    return diff_data

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

    if not export_from_html:
        # Generate fresh HTML report
        env = _setup_jinja_environment()
        template = env.get_template(LANGUAGE_TEMPLATES[language])
        env.globals["ws"] = workspace  # Make workspace available in templates

        # Get current report data
        json_path = write_report_json(workspace, **kwargs)
        current_data = json.loads(json_path.read_text())

        # Handle incremental mode
        if incremental:
            current_data = _generate_diff_report(current_data, workspace)

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