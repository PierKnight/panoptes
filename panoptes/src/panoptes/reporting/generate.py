from pathlib import Path
from .context import build
from jinja2 import Environment, FileSystemLoader
import json
from .pdf import html_to_pdf, markdown_to_pdf_via_html
import datetime
from typeguard import typechecked
from panoptes.utils.misc import get_diff_json 
from panoptes.utils.console import console
from deepdiff import DeepDiff
from panoptes.utils import logging

log = logging.get(__name__)

@typechecked
def write_report_json(ws: Path, **kwargs) -> Path:
    new_data = build(ws, imgbb_api_key=kwargs.get("imgbb_api_key", None))
    prev = ws / "report.json"
    if prev.exists():
        prev.rename(ws / "report.prev.json")
    json_path = ws / "report.json"
    json_path.write_text(json.dumps(new_data, indent=2))
    return json_path


@typechecked
def generate_report(ws: Path, incremental: bool, language: str, export_from_html: bool, **kwargs) -> tuple[Path, Path]:
    """
    Generate an HTML report and its PDF export for the collected data in the workspace.
    Args:
        ws (Path): The workspace directory where the report will be generated.
        incremental (bool): If True, generate the report in incremental mode, only processing new data
        since the last run.
    Returns:
        tuple[Path, Path]: Paths to the generated HTML and PDF report files.
    Raises:
        FileNotFoundError: If the workspace directory does not exist.
    """
    if not ws.exists():
        log.error(f"Workspace {ws} does not exist. Please run the [bold blue]\"collect\"[/bold blue] command first.")
        return  ("", "")

    domain = ws.name.split(".")[-2]  # Extract domain from workspace name

    html_path = ws / (f"osint-report-{domain}-{language}.html")
    pdf_path = ws / (f"osint-report-{domain}-{language}.pdf")

    if not export_from_html:
        TEMPLATE_ENV = Environment(
            loader=FileSystemLoader(Path(__file__).parent/"templates"),
            autoescape=True,  # automatically escape HTML
        )

        if language == "it":
            # Use the Italian template if specified
            TEMPLATE = TEMPLATE_ENV.get_template("report-it.html.j2")
        elif language == "en":
            # Use the English template by default
            TEMPLATE = TEMPLATE_ENV.get_template("report-en.html.j2")


        json_path = write_report_json(ws)
        TEMPLATE_ENV.globals["ws"] = ws  # make 'ws' available in the template
        
        current_json = json.loads(json_path.read_text())
        if incremental:
            # If incremental, get the diff from the previous report
            prev_json_path = ws / "report.prev.json"
            if prev_json_path.exists():
                previous_json = json.loads(prev_json_path.read_text())
                diff = DeepDiff(previous_json, current_json, ignore_order=True)
                # Create a new JSON object that includes only the changes
                diff_json = {}
                for key in diff.get('dictionary_item_added', []):
                    key = key.replace('root.', '')
                    diff_json[key] = current_json[key]
                for key in diff.get('values_changed', []):
                    key = key.replace('root.', '')
                    diff_json[key] = current_json[key]
                current_json = diff_json
                diff_path = ws / "report.diff.json"
                diff_path.write_text(json.dumps(current_json, indent=2))
            else:
                log.warning("No previous report found for incremental mode, using current data only.")

        with console.status("Rendering HTML from template..."):   
            html = TEMPLATE.render(current_json)
    
    
        ### Write rendered template to file
        ws.mkdir(parents=True, exist_ok=True)
        html_path.write_text(html)
    else:
        # If exporting from HTML, read the HTML content directly
        if not html_path.exists():
            log.error(f"HTML report file {html_path} does not exist. Please run the report generation first.")
            return ("", "")
        html = html_path.read_text()
   
    
    with console.status("Generating PDF from HTML..."):
        html_to_pdf(
            html_content=html,
            output_path=pdf_path,
        )
    return html_path, pdf_path