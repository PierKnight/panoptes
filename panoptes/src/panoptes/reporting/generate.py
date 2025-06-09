from pathlib import Path
from .context import build
from jinja2 import Environment, FileSystemLoader
import json
from .pdf import html_to_pdf, markdown_to_pdf_via_html
import datetime
from typeguard import typechecked


OLD_TEMPLATE_ENV = Environment(
    loader=FileSystemLoader(Path(__file__).parent/"templates"),
    trim_blocks=True,     # strip the first newline after a block
    lstrip_blocks=True    # strip spaces and tabs before a block
)

TEMPLATE_ENV = Environment(
    loader=FileSystemLoader(Path(__file__).parent/"templates"),
    autoescape=True,  # automatically escape HTML
)

TEMPLATE = TEMPLATE_ENV.get_template("report.html.j2")

@typechecked
def write_report_json(ws: Path) -> Path:
    new_data = build(ws)
    prev = ws / "report.json"
    if prev.exists():
        prev.rename(ws / "report.prev.json")
    json_path = ws / "report.json"
    json_path.write_text(json.dumps(new_data, indent=2))
    return json_path


@typechecked
def generate_report(ws: Path) -> tuple[Path, Path]:
    json_path = write_report_json(ws)
    TEMPLATE_ENV.globals["ws"] = ws  # make 'ws' available in the template
    
    # markdown = TEMPLATE.render(**json.loads(json_path.read_text()))
    html = TEMPLATE.render(**json.loads(json_path.read_text()))
    
    ### Write rendered template to file
    ws.mkdir(parents=True, exist_ok=True)
    html_path = ws / "osint-report.html"
    html_path.write_text(html)

    pdf_path = ws / "osint-report.pdf"
    
    '''
    markdown_to_pdf_via_html(
        markdown_content=html,
        output_path=pdf_path,
    )
    '''
    html_to_pdf(
        html_content=html,
        output_path=pdf_path,
       )
    return html_path, pdf_path