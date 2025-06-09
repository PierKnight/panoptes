from pathlib import Path
from panoptes.utils import logging
from weasyprint import HTML, CSS
import markdown2

log = logging.get(__name__)

def markdown_to_pdf_via_html(
        markdown_content: str,
        output_path: Path,
       ):
        """
        Convert markdown to PDF via HTML (no LaTeX dependencies)
        Requires: pip install weasyprint markdown2
        """
        try:
            
            
            # Convert markdown to HTML with extensions
            extras = [
                'tables',  # Pipe tables
                'fenced-code-blocks',
                'header-ids',
            ]
            

            html_content = markdown2.markdown(markdown_content, extras=extras)
            
            # CSS for better formatting
            css_content = """
            @page {
                margin: 1in;
                size: letter;
            }
            body { 
                font-family: 'Times New Roman', serif; 
                line-height: 1.6; 
                font-size: 11pt;
                color: #333;
            }
            h1 { 
                color: #2c3e50; 
                border-bottom: 2px solid #3498db; 
                padding-bottom: 5px;
                page-break-after: avoid;
            }
            h2 { 
                color: #34495e; 
                border-bottom: 1px solid #bdc3c7; 
                padding-bottom: 3px;
                page-break-after: avoid;
            }
            h3 { 
                color: #34495e; 
                page-break-after: avoid;
            }
            h4 { 
                color: #7f8c8d; 
                page-break-after: avoid;
            }
            table { 
                border-collapse: collapse; 
                width: 100%; 
                margin: 20px 0;
                page-break-inside: avoid;
            }
            th, td { 
                border: 1px solid #ddd; 
                padding: 8px; 
                text-align: left; 
            }
            th { 
                background-color: #f8f9fa; 
                font-weight: bold;
            }
            img { 
                max-width: 100%; 
                height: auto; 
                page-break-inside: avoid;
            }
            pre, code {
                background-color: #f8f9fa;
                border: 1px solid #e9ecef;
                border-radius: 3px;
                padding: 2px 4px;
                font-family: 'Courier New', monospace;
            }
            pre {
                padding: 10px;
                overflow-x: auto;
            }
            .data-leak {
                background-color: #fce4ec; /* Light pink for data leaks */
                border-left: 5px solid #e91e63; /* Darker pink border */
                padding: 5px;
                margin: 20px 5;
                font-size: 8pt;
            }
            .record-table {
                table-width: 85%;
                border-collapse: collapse;
            }

            .record-table th,
            .record-table td {
                text-align: left;
                padding: 8px;
                border: 1px solid #ddd;
                word-wrap: break-word;
            }

            /* Specific column widths */
            .record-table th:nth-child(1),
            .record-table td:nth-child(1) {
                width: 30%;
            }

            .record-table th:nth-child(2),
            .record-table td:nth-child(2) {
                width: 20%;
            }

            .record-table th:nth-child(3),
            .record-table td:nth-child(3) {
                width: 10%;
            }

            .record-table th:nth-child(4),
            .record-table td:nth-child(4) {
                width: 40%;
            }

            .record-table th {
                background-color: #f2f2f2;
            }
            """
            
            # Create complete HTML document
            full_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Document</title>
            </head>
            <body>
                {html_content}
            </body>
            </html>
            """
            
            # Convert to PDF
            HTML(string=full_html).write_pdf(
                str(output_path),
                stylesheets=[CSS(string=css_content)]
            )
            
            log.info(f"✅ PDF created via HTML: {output_path}")
            return str(output_path)
            
        except ImportError:
            log.error("WeasyPrint not installed. Install with: pip install weasyprint markdown2")
            raise
        except Exception as e:
            log.error(f"❌ Error converting via HTML: {e}")
            raise
    

def html_to_pdf(
    html_content: str,
    output_path: Path,
):
    """
    Convert HTML to PDF via WeasyPrint (no LaTeX or Markdown dependencies).
    Expects input HTML to be valid and complete (i.e., includes <html> and <body> tags).

    Args:
        html_content (str): The HTML content to convert to PDF.
        output_path (Path): The path where the generated PDF will be saved.
    Returns:
        str: The path to the generated PDF file.
    Raises:
        FileNotFoundError: If the CSS file is not found.
    """
    try:
        # css_content is in ./css/style.css
        css_path = Path(__file__).parent / "css" / "style.css"
        if not css_path.exists():
            log.error(f"CSS file not found: {css_path}")
            raise FileNotFoundError(f"CSS file not found: {css_path}")
        css_content = css_path.read_text(encoding="utf-8")

        # We expect html_content to be a fully rendered HTML document.
        HTML(string=html_content).write_pdf(
            str(output_path),
            stylesheets=[CSS(string=css_content)]
        )
        log.info(f"✅ PDF created via HTML template: {output_path}")
        return str(output_path)
    except ImportError:
        log.error("WeasyPrint not installed. Install with: pip install weasyprint")
        raise
    except Exception as e:
        log.error(f"❌ Error converting HTML to PDF: {e}")
        raise