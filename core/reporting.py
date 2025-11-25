import json
import os

class ReportGenerator:
    def __init__(self, output_dir='reports'):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def generate_json(self, sample, analysis_data):
        report = {
            'filename': sample.filename,
            'md5': sample.md5,
            'sha256': sample.sha256,
            'analysis': analysis_data
        }
        path = os.path.join(self.output_dir, f"{sample.filename}_{sample.id}.json")
        with open(path, 'w') as f:
            json.dump(report, f, indent=4)
        return path

    def generate_html(self, sample, analysis_data):
        # Basic HTML template
        html = f"""
        <html>
        <head>
            <title>Report: {sample.filename}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .section {{ margin-bottom: 20px; border: 1px solid #ddd; padding: 10px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Analysis Report: {sample.filename}</h1>
            <div class="section">
                <h2>Metadata</h2>
                <p><strong>MD5:</strong> {sample.md5}</p>
                <p><strong>SHA256:</strong> {sample.sha256}</p>
            </div>
        """
        
        if 'imports' in analysis_data:
            html += """<div class="section"><h2>Imports</h2><table><tr><th>DLL</th><th>Function</th></tr>"""
            for dll, funcs in analysis_data['imports'].items():
                for func in funcs:
                    name = func['name'] if isinstance(func, dict) else str(func)
                    html += f"<tr><td>{dll}</td><td>{name}</td></tr>"
            html += "</table></div>"

        if 'strings' in analysis_data:
            html += """<div class="section"><h2>Strings (First 100)</h2><pre>"""
            html += "\n".join(analysis_data['strings'][:100])
            html += "</pre></div>"

        html += "</body></html>"
        
        path = os.path.join(self.output_dir, f"{sample.filename}_{sample.id}.html")
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
        return path
