import json

from dojo.models import Finding


class CoverityScanParser:
    """Parser for Coverity Scan JSON files."""

    def get_scan_types(self):
        return ["Coverity Scan JSON Report"]

    def get_label_for_scan_types(self, scan_type):
        return "Coverity Scan JSON Report"
    
    def get_description_for_scan_types(self, scan_type):
        return "Import Coverity Scan JSON output (coverity scan --local-format json --local <json_file>)"

    def get_findings(self, file, test):
        findings = list()
        data = json.load(file)

        for issue in data["issues"]:
            checker_properties = issue["checkerProperties"]

            # Handle only security findings
            if not "SECURITY" in checker_properties["issueKinds"]:
                continue

            mitigation = ""
            for event in issue["events"]:
                if event.get("main"):
                    long_description = checker_properties.get("subcategoryLongDescription")
                    event_description = event.get("eventDescription")
                    if long_description == event_description:
                        description = long_description
                    else:
                        description = f"{long_description}\n{event_description}"

                if event.get("remediation"):
                    mitigation = event.get("eventDescription")

            vuln_id = "/".join([issue.get("checkerName"), issue.get("subcategory", "")])

            finding = Finding(
                test=test,
                title=checker_properties.get("subcategoryShortDescription"),
                severity=self.convert_impact(checker_properties.get("impact")),
                description=description,
                file_path=issue.get("strippedMainEventFilePathname"),
                line=issue.get("mainEventLineNumber"),
                static_finding=True,
                dynamic_finding=False,
                nb_occurences=issue.get("occurrenceCountForMK"),
                cwe=int(checker_properties.get("cweCategory")),
                mitigation=mitigation,
                impact=checker_properties.get("subcategoryLocalEffect"),
                vuln_id_from_tool=vuln_id,
            )

            findings.append(finding)
        
        return findings
    
    def convert_impact(self, val):
        if val is None:
            return "Info"
        if "Audit" == val:
            return "Info"
        if "Low" == val:
            return "Low"
        if "Medium" == val:
            return "Medium"
        if "High" == val:
            return "High"
        raise ValueError(f"Unknown value for Coverity impact {val}")