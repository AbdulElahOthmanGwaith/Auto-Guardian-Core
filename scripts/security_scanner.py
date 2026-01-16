import os
import json
import datetime

class SecurityScanner:
    def __init__(self, target_dir):
        self.target_dir = target_dir
        self.results = {
            "scan_time": str(datetime.datetime.now()),
            "vulnerabilities": [],
            "summary": {"high": 0, "medium": 0, "low": 0}
        }

    def scan_files(self):
        print(f"Starting security scan on: {self.target_dir}")
        for root, dirs, files in os.walk(self.target_dir):
            for file in files:
                if file.endswith(('.py', '.js', '.html')):
                    self._check_file(os.path.join(root, file))
        
        self._save_results()

    def _check_file(self, file_path):
        # Simple pattern matching for demonstration
        patterns = {
            "hardcoded_api_key": {"regex": "api_key =", "severity": "high", "desc": "Potential hardcoded API key found"},
            "insecure_eval": {"regex": "eval\(", "severity": "high", "desc": "Use of insecure eval() function"},
            "todo_comment": {"regex": "TODO:", "severity": "low", "desc": "Unresolved TODO comment"}
        }
        
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                for key, data in patterns.items():
                    if data["regex"] in content:
                        self.results["vulnerabilities"].append({
                            "file": file_path,
                            "issue": key,
                            "severity": data["severity"],
                            "description": data["desc"]
                        })
                        self.results["summary"][data["severity"]] += 1
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")

    def _save_results(self):
        output_path = os.path.join(self.target_dir, 'public/data/security_scan_latest.json')
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=4)
        print(f"Scan complete. Results saved to {output_path}")

if __name__ == "__main__":
    scanner = SecurityScanner('.')
    scanner.scan_files()
