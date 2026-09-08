package myapp.model;

public class ScanSummary {

    private final int passed;
    private final int warnings;
    private final int errors;
    private final int highRisk;
    private final int mediumRisk;
    private final int lowRisk;
    private final int securityScore;
    private final String riskLevel;

    public ScanSummary(
            int passed,
            int warnings,
            int errors,
            int highRisk,
            int mediumRisk,
            int lowRisk,
            int securityScore,
            String riskLevel) {

        this.passed = passed;
        this.warnings = warnings;
        this.errors = errors;
        this.highRisk = highRisk;
        this.mediumRisk = mediumRisk;
        this.lowRisk = lowRisk;
        this.securityScore = securityScore;
        this.riskLevel = riskLevel;
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
}