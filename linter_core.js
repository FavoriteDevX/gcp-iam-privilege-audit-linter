export class GCPIamPrivilegeAuditLinter {
  constructor() {
    // Dangerous legacy rules defined by GCP security consensus benchmarks
    this.primitiveRoles = ["roles/owner", "roles/editor", "roles/viewer"];
  }

  /**
   * Inspects local policy files or API resource outputs before deployment phases
   * @param {Object} iamPolicyBindingsObject 
   */
  auditPolicyBindings(iamPolicyBindingsObject) {
    console.log("🕵️ Sweeping target Google Cloud IAM Policy deployment templates against compliance matrices...");
    const report = { passed: true, issuesInterception: [] };

    const bindings = iamPolicyBindingsObject.bindings || [];

    bindings.forEach(binding => {
      const role = binding.role;
      const members = binding.members || [];

      // Check 1: Primitive / Over-privileged roles detection rule
      if (this.primitiveRoles.includes(role)) {
        report.passed = false;
        report.issuesInterception.push({
          severity: "CRITICAL",
          fault: `Usage of legacy primitive system role identifier caught: '${role}'. This grants over-scoped domain access. Transition to fine-grained granular IAM roles.`
        });
      }

      // Check 2: Blind wildcard global permission exposures
      members.forEach(member => {
        if (member.toLowerCase() === "allauthenticatedusers" || member.toLowerCase() === "allusers") {
          report.passed = false;
          report.issuesInterception.push({
            severity: "HIGH",
            fault: `Public accessibility exposure! Structural token member matching validation incorporates '${member}' directly inside role assignment boundary [${role}].`
          });
        }
      });
    });

    this.displayAuditReport(report);
    return report;
  }

  displayAuditReport(report) {
    console.log("\n==========================================================================");
    console.log("🛡️ GOOGLE DEV SYSTEM FIREWALL: IAM COMPLIANCE TELEMETRY REPORT");
    console.log("==========================================================================");
    
    if (report.passed) {
        console.log("🟩 PASS: IAM configuration alignments adhere to the Principle of Least Privilege.");
        return;
    }

    report.issuesInterception.forEach(issue => {
        const marker = issue.severity === "CRITICAL" ? "🚨" : "⚠️";
        console.log(`${marker} [${issue.severity}] - Description: ${issue.fault}`);
    });
  }
}

// Running Demo Test Verification Trace Hooks
const policyHarness = {
  bindings: [
    {
      role: "roles/editor", // Primitive exploitation
      members: ["serviceAccount:analytics-worker@://gserviceaccount.com"]
    },
    {
      role: "roles/storage.objectViewer",
      members: ["allUsers"] // Public exposure leakage
    }
  ]
};

const auditor = new GCPIamPrivilegeAuditLinter();
auditor.auditPolicyBindings(policyHarness);
