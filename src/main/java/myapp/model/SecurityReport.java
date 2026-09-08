
package myapp.model;

import java.util.List;

public class SecurityReport {

    private final String tool;
    private final String region;
    private final String scanMode;
    private final String targets;
    private final String timestamp;
    private final int totalFindings;
    private final int passed;
    private final int warnings;
    private final int errors;
    private final int highRisk;
    private final int mediumRisk;
    private final int lowRisk;
    private final int securityScore;
    private final String riskLevel;
    private final List<SecurityFinding> findings;

    public SecurityReport(
            String tool,
            String region,
            String scanMode,
            String targets,
            String timestamp,
            int totalFindings,
            int passed,
            int warnings,
            int errors,
            int highRisk,
            int mediumRisk,
            int lowRisk,
            int securityScore,
            String riskLevel,
            List<SecurityFinding> findings) {

        this.tool = tool;
        this.region = region;
        this.scanMode = scanMode;
        this.targets = targets;
        this.timestamp = timestamp;
        this.totalFindings = totalFindings;
        this.passed = passed;
        this.warnings = warnings;
        this.errors = errors;
        this.highRisk = highRisk;
        this.mediumRisk = mediumRisk;
        this.lowRisk = lowRisk;
        this.securityScore = securityScore;
        this.riskLevel = riskLevel;
        this.findings = findings;
    }

    public String getTool() {
        return tool;
    }

    public String getRegion() {
        return region;
    }

    public String getScanMode() {
        return scanMode;
    }

    public String getTargets() {
    return targets;
    }
    
    public String getTimestamp() {
        return timestamp;
    }

    public int getTotalFindings() {
        return totalFindings;
    }

    public int getPassed() {
        return passed;
    }

    public int getWarnings() {
        return warnings;
    }

    public int getErrors() {
        return errors;
    }

    public int getHighRisk() {
        return highRisk;
    }

    public int getMediumRisk() {
        return mediumRisk;
    }

    public int getLowRisk() {
        return lowRisk;
    }

    public int getSecurityScore() {
        return securityScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public List<SecurityFinding> getFindings() {
        return findings;
    }
}

