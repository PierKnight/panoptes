from pathlib import Path
from .context import build
from jinja2 import Environment, FileSystemLoader
import json
#from .pdf import markdown_to_pdf    # your pandoc/weasyprint helper

TEMPLATE_ENV = Environment(loader=FileSystemLoader(Path(__file__).parent/"templates"))
TEMPLATE = TEMPLATE_ENV.get_template("report.md.j2")

def write_report_json(ws: Path) -> Path:
    new_data = build(ws)
    prev = ws / "report.json"
    if prev.exists():
        prev.rename(ws / "report.prev.json")
    json_path = ws / "report.json"
    json_path.write_text(json.dumps(new_data, indent=2))
    return json_path

def generate_report(ws: Path) -> Path:
    json_path = write_report_json(ws)
    #markdown = TEMPLATE.render(**json.loads(json_path.read_text()))
    pdf_path = ws / "report.pdf"
    #markdown_to_pdf(markdown, pdf_path)
    return pdf_path