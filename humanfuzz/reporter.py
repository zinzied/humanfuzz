"""
Reporting module for HumanFuzz.
"""

import logging
import json
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
import html

logger = logging.getLogger(__name__)

class Reporter:
    """
    Generates reports of fuzzing results.
    """
    
    def __init__(self):
        """Initialize the reporter."""
        pass
        
    def generate(self, findings: List[Dict], output_file: str) -> None:
        """
        Generate a report of fuzzing results.
        
        Args:
            findings: List of vulnerability findings
            output_file: Path to the output file
        """
        logger.info(f"Generating report with {len(findings)} findings")
        
        # Determine the report format based on file extension
        _, ext = os.path.splitext(output_file)
        
        if ext.lower() == '.json':
            self._generate_json_report(findings, output_file)
        elif ext.lower() == '.html':
            self._generate_html_report(findings, output_file)
        elif ext.lower() == '.md':
            self._generate_markdown_report(findings, output_file)
        else:
            logger.warning(f"Unknown report format: {ext}. Defaulting to HTML.")
            self._generate_html_report(findings, output_file)
            
    def _generate_json_report(self, findings: List[Dict], output_file: str) -> None:
        """Generate a JSON report."""
        report = {
            "generated_at": datetime.now().isoformat(),
            "total_findings": len(findings),
            "findings": findings
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        logger.info(f"JSON report saved to {output_file}")
        
    def _generate_markdown_report(self, findings: List[Dict], output_file: str) -> None:
        """Generate a Markdown report."""
        with open(output_file, 'w') as f:
            f.write("# HumanFuzz Vulnerability Report\n\n")
            f.write(f"Generated at: {datetime.now().isoformat()}\n\n")
            f.write(f"Total findings: {len(findings)}\n\n")
            
            # Group findings by severity
            severity_groups = {"high": [], "medium": [], "low": []}
            for finding in findings:
                severity = finding.get("severity", "low")
                severity_groups[severity].append(finding)
                
            # Write findings by severity
            for severity, group in severity_groups.items():
                if group:
                    f.write(f"## {severity.upper()} Severity ({len(group)})\n\n")
                    
                    for i, finding in enumerate(group, 1):
                        f.write(f"### {i}. {finding.get('type', 'Unknown')} - {finding.get('url', 'Unknown URL')}\n\n")
                        f.write(f"**Description:** {finding.get('description', 'No description')}\n\n")
                        f.write(f"**Payload:** `{finding.get('payload', 'No payload')}`\n\n")
                        
                        if finding.get('evidence'):
                            f.write("**Evidence:**\n\n```\n")
                            f.write(finding.get('evidence', ''))
                            f.write("\n```\n\n")
                        
                        f.write("---\n\n")
                        
        logger.info(f"Markdown report saved to {output_file}")
        
    def _generate_html_report(self, findings: List[Dict], output_file: str) -> None:
        """Generate an HTML report."""
        # Count findings by severity
        severity_counts = {"high": 0, "medium": 0, "low": 0}
        for finding in findings:
            severity = finding.get("severity", "low")
            severity_counts[severity] += 1
            
        # Group findings by type
        type_groups = {}
        for finding in findings:
            finding_type = finding.get("type", "unknown")
            if finding_type not in type_groups:
                type_groups[finding_type] = []
            type_groups[finding_type].append(finding)
            
        # Generate HTML
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HumanFuzz Vulnerability Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .summary {{
            display: flex;
            justify-content: space-between;
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .severity-count {{
            text-align: center;
            padding: 10px;
            border-radius: 5px;
            margin: 0 5px;
        }}
        .high {{
            background-color: #f8d7da;
            color: #721c24;
        }}
        .medium {{
            background-color: #fff3cd;
            color: #856404;
        }}
        .low {{
            background-color: #d1ecf1;
            color: #0c5460;
        }}
        .finding {{
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .evidence {{
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: monospace;
            white-space: pre-wrap;
        }}
        .payload {{
            font-family: monospace;
            background-color: #f1f1f1;
            padding: 2px 5px;
            border-radius: 3px;
        }}
    </style>
</head>
<body>
    <h1>HumanFuzz Vulnerability Report</h1>
    <p>Generated at: {datetime.now().isoformat()}</p>
    
    <div class="summary">
        <div>
            <h2>Summary</h2>
            <p>Total findings: {len(findings)}</p>
        </div>
        <div style="display: flex;">
            <div class="severity-count high">
                <h3>High</h3>
                <p>{severity_counts['high']}</p>
            </div>
            <div class="severity-count medium">
                <h3>Medium</h3>
                <p>{severity_counts['medium']}</p>
            </div>
            <div class="severity-count low">
                <h3>Low</h3>
                <p>{severity_counts['low']}</p>
            </div>
        </div>
    </div>
    
    <h2>Findings</h2>
"""
        
        # Add findings by type
        for finding_type, group in type_groups.items():
            html_content += f"<h3>{finding_type.upper()} ({len(group)})</h3>\n"
            
            for finding in group:
                severity = finding.get("severity", "low")
                url = html.escape(finding.get("url", "Unknown URL"))
                description = html.escape(finding.get("description", "No description"))
                payload = html.escape(finding.get("payload", "No payload"))
                evidence = html.escape(finding.get("evidence", "No evidence"))
                
                html_content += f"""
    <div class="finding">
        <div class="finding-header">
            <h4>{html.escape(finding.get('type', 'Unknown'))}</h4>
            <span class="severity-count {severity}">{severity.upper()}</span>
        </div>
        <p><strong>URL:</strong> {url}</p>
        <p><strong>Description:</strong> {description}</p>
        <p><strong>Payload:</strong> <span class="payload">{payload}</span></p>
        <div>
            <p><strong>Evidence:</strong></p>
            <div class="evidence">{evidence}</div>
        </div>
    </div>
"""
                
        html_content += """
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html_content)
            
        logger.info(f"HTML report saved to {output_file}")
