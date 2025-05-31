import pypandoc
from pathlib import Path
from osint_app.utils import logging

log = logging.get(__name__)

def markdown_to_pdf(
        markdown_content: str,
        output_path: Path,
        *,
        preserve_headers=True,
        include_toc=False
       ):
        """
        Convert markdown content to PDF
        
        Args:
            markdown_content: Rendered markdown content
            output_path: Path to save the PDF file
            preserve_headers: Keep header hierarchy (up to ####)
            include_toc: Include table of contents
        """
        
        # Pandoc extra arguments for better formatting
        extra_args = [
            '--pdf-engine=xelatex',  # Better Unicode support
            '--variable', 'geometry:margin=1in',  # Page margins
            '--variable', 'fontsize=11pt',  # Font size
            '--variable', 'linestretch=1.2',  # Line spacing
        ]
        
        # Add table of contents if requested
        if include_toc:
            extra_args.extend(['--toc', '--toc-depth=4'])
        
        # Preserve header levels up to #### (level 4)
        if preserve_headers:
            extra_args.extend(['--shift-heading-level-by=0'])
        
        try:
            pypandoc.convert_text(
                markdown_content,
                'pdf',
                format='md',
                outputfile=str(output_path),
                extra_args=extra_args
            )
            log.info(f"✅ PDF created successfully: {output_path}")
            return str(output_path)
            
        except Exception as e:
            log.error(f"❌ Error converting to PDF: {e}")
            raise


# Alternative: HTML to PDF approach (no LaTeX required)
def markdown_to_pdf_via_html(
        markdown_content: str,
        output_path: Path,
        *,
        include_toc=False
       ):
        """
        Convert markdown to PDF via HTML (no LaTeX dependencies)
        Requires: pip install weasyprint markdown2
        """
        try:
            import markdown2
            from weasyprint import HTML, CSS
            
            # Convert markdown to HTML with extensions
            extras = [
                'tables',  # Pipe tables
                'fenced-code-blocks',
                'header-ids',
            ]
            
            if include_toc:
                extras.append('toc')
            
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