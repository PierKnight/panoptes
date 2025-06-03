from pathlib import Path
from .context import build
from jinja2 import Environment, FileSystemLoader
import json
from .pdf import markdown_to_pdf_via_html


def escape_markdown_chars(text: str) -> str:
    """
    Escape characters that have special meaning in Markdown
    """
    if not isinstance(text, str):
        return text
    
    # Escape underscores, asterisks, backticks, and other special chars
    escape_chars = {
        '_': r'\_',
        '*': r'\*',
        '`': r'\`',
        '[': r'\[',
        ']': r'\]',
        '(': r'\(',
        ')': r'\)',
        '#': r'\#',
        '+': r'\+',
        '-': r'\-',
        '.': r'\.',
        '!': r'\!',
        '{': r'\{',
        '}': r'\}',
        '|': r'\|',
        '^': r'\^',
        '<': r'\<',
        '>': r'\>',
        '~': r'\~',
    }

    result = text
    for char, escaped in escape_chars.items():
        result = result.replace(char, escaped)
    
    return result

TEMPLATE_ENV = Environment(
    loader=FileSystemLoader(Path(__file__).parent/"templates"),
    trim_blocks=True,     # strip the first newline after a block
    lstrip_blocks=True    # strip spaces and tabs before a block
)

TEMPLATE_ENV.filters["escape_md"] = escape_markdown_chars

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
    
    ### Write markdown to file
    ws.mkdir(parents=True, exist_ok=True)
    markdown_path = ws / "osint-report.md"
    markdown_path.write_text(markdown)

    pdf_path = ws / "osint-report.pdf"
    markdown_path = ws / "osint-report.md"
    markdown_to_pdf_via_html(
        markdown_content=markdown,
        output_path=pdf_path,
        include_toc=True
        )
    return markdown_path, pdf_path