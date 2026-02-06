"""Report generation module"""

import json
from datetime import datetime


class ReportGenerator:
    """Generates security scan reports"""
    
    def __init__(self, findings):
        self.findings = findings
    
    def save_json(self, filepath):
        """Save findings as JSON report"""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.findings, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"Error saving report: {str(e)}")
            return False
    
    def get_summary(self):
        """Get summary statistics"""
        summary = {
            "total_checks": len(self.findings.get("scan_results", {})),
            "risk_levels": self.findings.get("risk_summary", {}),
            "timestamp": self.findings.get("timestamp")
        }
        return summary
    
    def generate_text_report(self):
        """Generate human-readable text report"""
        lines = [
            "=" * 70,
            "YAHA SECURITY SCAN REPORT",
            "=" * 70,
            f"Target: {self.findings['target']}",
            f"Timestamp: {self.findings['timestamp']}",
            "",
            "RISK SUMMARY",
            "-" * 70,
        ]
        
        summary = self.findings.get("risk_summary", {})
        for risk_level in ["critical", "high", "medium", "low", "info"]:
            count = summary.get(risk_level, 0)
            lines.append(f"{risk_level.upper()}: {count}")
        
        lines.extend([
            "",
            "DETAILED FINDINGS",
            "-" * 70,
        ])
        
        for check_name, results in self.findings.get("scan_results", {}).items():
            lines.append(f"\n{check_name.upper()}")
            lines.append("  " + "-" * 66)
            
            if isinstance(results, dict):
                for key, value in results.items():
                    if isinstance(value, (list, dict)):
                        lines.append(f"  {key}: {json.dumps(value, indent=2)}")
                    else:
                        lines.append(f"  {key}: {value}")
        
        return "\n".join(lines)
