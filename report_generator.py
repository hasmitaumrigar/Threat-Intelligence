# report_generator.py
from fpdf import FPDF
from datetime import datetime
import re

def clean_text(text: str) -> str:
    """Remove emojis and non-latin-1 characters for PDF compatibility."""
    return text.encode("latin-1", errors="ignore").decode("latin-1")

def generate_report(result: dict) -> bytes:
    pdf = FPDF()
    pdf.add_page()

    # Title
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, "Threat Intelligence Report", ln=True, align="C")
    pdf.ln(5)

    # Timestamp
    pdf.set_font("Arial", "I", 10)
    pdf.cell(200, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(5)

    # Horizontal line
    pdf.set_draw_color(200, 200, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    # Content
    for key, value in result.items():
        # FIX: clean both key and value to remove emojis
        clean_key   = clean_text(str(key))
        clean_value = clean_text(str(value))

        pdf.set_font("Arial", "B", 11)
        pdf.cell(50, 8, clean_key + ":", ln=False)
        pdf.set_font("Arial", size=11)
        pdf.multi_cell(0, 8, clean_value)

    return pdf.output(dest="S").encode("latin-1")