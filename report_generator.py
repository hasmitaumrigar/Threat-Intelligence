# report_generator.py
from fpdf import FPDF

def generate_report(result: dict) -> bytes:
    pdf = FPDF()
    pdf.add_page()
    
    # Title
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, "Threat Intelligence Report", ln=True, align="C")
    pdf.ln(10)
    
    # Timestamp
    pdf.set_font("Arial", "I", 10)
    from datetime import datetime
    pdf.cell(200, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(5)
    
    # Content
    pdf.set_font("Arial", size=11)
    for key, value in result.items():
        pdf.set_font("Arial", "B", 11)
        pdf.cell(60, 8, str(key) + ":", ln=False)
        pdf.set_font("Arial", size=11)
        pdf.multi_cell(0, 8, str(value))

    # Return as bytes
    return pdf.output(dest="S").encode("latin-1")
