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
from bs4 import BeautifulSoup
import uuid
import re


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

    return ".".join(workspace.name.split(".")[:-1])

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

def add_table_of_contents(html_content: str) -> str:
    """
    Add a dynamic table of contents to the HTML report with page numbers.
    
    Args:
        html_content: The HTML content to process
        
    Returns:
        Processed HTML with TOC
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Find the TOC div
    toc_div = soup.find('div', {'id': 'table-of-contents'})
    if not toc_div:
        return html_content  # No TOC section found
    
    # Find all headings in the document (h1-h4)
    headings = soup.find_all(['h1', 'h2', 'h3', 'h4'])
    
    # Create the TOC structure
    toc_ul = soup.new_tag('ul')
    current_ul = toc_ul
    current_level = 1
    
    for heading in headings:
        # Ensure heading has an ID
        if not heading.get('id'):
            heading['id'] = str(uuid.uuid4())
        
        # Create TOC entry
        level = int(heading.name[1])
        
        # Adjust UL nesting based on heading level
        while level > current_level:
            new_ul = soup.new_tag('ul')
            last_li = current_ul.contents[-1] if current_ul.contents else None
            if last_li and last_li.name == 'li':
                last_li.append(new_ul)
                current_ul = new_ul
                current_level += 1
            else:
                break  # prevent nesting errors
            
        while level < current_level:
            current_ul = current_ul.parent
            current_level -= 1
            
        # Create the TOC item
        li = soup.new_tag('li')
        a = soup.new_tag('a', href=f"#{heading['id']}")


        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

        # If the tag contains an email, add class to highlight it
        if re.match(email_pattern, heading.get_text().lower()):
            a['class'] = 'leaked-email-toc'

        a.string = heading.get_text()
        li.append(a)
        current_ul.append(li)
    
    # Add the TOC to the document
    toc_container = toc_div.find('div', class_='toc')
    if toc_container:
        toc_container.append(toc_ul)
    
    return str(soup)

@typechecked
def generate_report(
    workspace: Path,
    incremental: bool = False,
    language: str = "en",
    export_from_html: bool = False,
    theme: str = "iei",
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
    headers_url_path = Path(__file__).parent / "templates" / "designs" / f"headers-url.json"
    titlepages_url_path = Path(__file__).parent / "templates" / "designs" / f"titlepages-url.json"
    
    html_path = workspace / f"osint-report-{domain}-{language}.html"
    pdf_path = workspace / f"osint-report-{domain}-{language}.pdf"
    report_json_path = workspace / "report.json"

    if not export_from_html:
        # Generate fresh HTML report
        env = _setup_jinja_environment()
        template = env.get_template(LANGUAGE_TEMPLATES[language])
        env.globals["ws"] = workspace  # Make workspace available in templates

        # Setup design variables
        if not headers_url_path.exists() or not titlepages_url_path.exists():
            log.error(f"Required design files not found: {headers_url_path} or {titlepages_url_path}")
            raise FileNotFoundError(f"Design files not found in {TEMPLATE_DIR}")
    
        if headers_url_path.exists():
            env.globals["headers"] = json.loads(headers_url_path.read_text())
        
        if titlepages_url_path.exists():
            env.globals["titlepages"] = json.loads(titlepages_url_path.read_text())

        env.globals["theme"] = theme

        # Get current report data
        report_dict = build(workspace, imgbb_api_key=kwargs.get("imgbb_api_key"))

        merged_report = dict()
        incremental_data = dict()

        # If there is an existing report, merge it (so that we always have all data retrieved)
        if report_json_path.exists():
            log.info(f"Loading existing report data from {report_json_path}")

            # Load existing report data
            old_data = json.loads(report_json_path.read_text())

            # Handle incremental mode
            if incremental:          
                incremental_data = _dict_diff(report_dict, old_data)
                incremental_data["is_incremental"] = True
                html_path = workspace / f"osint-report-{domain}-{language}-incremental-{datetime.datetime.now().strftime('%Y%m%d')}.html"
                pdf_path = workspace / f"osint-report-{domain}-{language}-incremental-{datetime.datetime.now().strftime('%Y%m%d%')}.pdf"
                diff_path = workspace/"report.diff.json"
                diff_path.write_text(json.dumps(incremental_data, indent=2)) 

            # Merge old data with new data
            merged_report = _dict_union(report_dict, old_data)
        else:
            if incremental:
                log.warning("No existing report found for incremental mode, generating full report instead.")
            merged_report = report_dict
        
        current_data = incremental_data if len(incremental_data) > 0 else merged_report 

        if "is_incremental" in report_dict:
            del report_dict["is_incremental"]  # We don't need this in the json file

        write_report_json(workspace, merged_report, **kwargs)
                
        # Render template with current data
        with console.status("Rendering HTML from template..."):
            html = template.render(current_data)
    
    else:
        # Use existing HTML file
        if not html_path.exists():
            log.error(f"HTML report {html_path} does not exist")
            raise FileNotFoundError(f"HTML report {html_path} not found")
        html = html_path.read_text()

    with console.status("Adding Table of Contents..."):
        html = add_table_of_contents(html) 

    # Ensure workspace exists and write HTML
    workspace.mkdir(parents=True, exist_ok=True)
    html_path.write_text(html)

    # Generate PDF from HTML
    with console.status("Generating PDF from HTML..."):
        html_to_pdf(html_content=html, output_path=pdf_path)

    return html_path, pdf_path