import { PackageAnalyzerPlugin, PackageContext } from "./base";
import { Issue } from "../analyzer";
import axios from "axios";

interface OSVVulnerability {
  id: string;
  summary: string;
  details?: string;
  severity?: Array<{
    type: string;
    score: string;
  }>;
  database_specific?: {
    severity?: string;
  };
  affected?: Array<{
    package: {
      ecosystem: string;
      name: string;
    };
    ranges?: Array<{
      type: string;
      events: Array<{
        introduced?: string;
        fixed?: string;
      }>;
    }>;
    versions?: string[];
  }>;
}

interface OSVQueryResponse {
  vulns?: OSVVulnerability[];
}

export class CVEAnalyzer implements PackageAnalyzerPlugin {
  name = "cve";
  type = "package" as const;
  requiresNetwork = true;

  private mapSeverity(
    vuln: OSVVulnerability,
    context: PackageContext,
  ): "critical" | "high" | "medium" | "low" {
    const cveConfig = context.config.analyzers?.cve;
    const criticalThreshold = cveConfig?.criticalThreshold ?? 9.0;
    const highThreshold = cveConfig?.highThreshold ?? 7.0;
    const mediumThreshold = cveConfig?.mediumThreshold ?? 4.0;

    if (vuln.severity && vuln.severity.length > 0) {
      for (const sev of vuln.severity) {
        if (sev.type === "CVSS_V3") {
          const score = parseFloat(sev.score.split(" ")[0]);
          if (score >= criticalThreshold) return "critical";
          if (score >= highThreshold) return "high";
          if (score >= mediumThreshold) return "medium";
          return "low";
        }
      }
    }

    if (vuln.database_specific?.severity) {
      const severity = vuln.database_specific.severity.toLowerCase();
      if (severity === "critical") return "critical";
      if (severity === "high") return "high";
      if (severity === "moderate" || severity === "medium") return "medium";
      if (severity === "low") return "low";
    }

    return "high";
  }

  async analyze(context: PackageContext): Promise<Issue[]> {
    const issues: Issue[] = [];
    const { name, version, config } = context;

    const cveConfig = config.analyzers?.cve;
    if (cveConfig?.enabled === false) {
      return issues;
    }

    const timeout = cveConfig?.timeout ?? 5000;

    try {
      const response = await axios.post(
        "https://api.osv.dev/v1/query",
        {
          version: version,
          package: {
            name: name,
            ecosystem: "npm",
          },
        },
        {
          timeout: timeout,
          headers: {
            "Content-Type": "application/json",
          },
        },
      );

      const data: OSVQueryResponse = response.data;

      if (data.vulns && data.vulns.length > 0) {
        for (const vuln of data.vulns) {
          const severity = this.mapSeverity(vuln, context);
          const message = vuln.summary || vuln.details || "Known vulnerability";

          issues.push({
            type: "cve",
            message: `${vuln.id}: ${message}`,
            severity: severity,
          });
        }
      }
    } catch {
      // Skip errors (e.g., timeout, network issues)
    }

    return issues;
  }
}
