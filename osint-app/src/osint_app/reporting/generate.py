from pathlib import Path
from .context import build
from jinja2 import Environment, FileSystemLoader
import json
#from .pdf import markdown_to_pdf    # your pandoc/weasyprint helper

TEMPLATE_ENV = Environment(
    loader=FileSystemLoader(Path(__file__).parent/"templates"),
    trim_blocks=True,     # strip the first newline after a block
    lstrip_blocks=True    # strip spaces and tabs before a block
)

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
    TEMPLATE_ENV.globals["ws"] = ws  # make 'ws' available in the template
    markdown = TEMPLATE.render(**json.loads(json_path.read_text()))
    print(f"Generated report markdown for {ws.name}:\n{markdown}")  # Print first 100 chars for brevity
    pdf_path = ws / "report.pdf"
    #markdown_to_pdf(markdown, pdf_path)
    return pdf_path