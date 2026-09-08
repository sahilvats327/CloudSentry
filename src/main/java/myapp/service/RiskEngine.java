
package myapp.service;

import myapp.model.ScanSummary;
import myapp.model.SecurityFinding;

import java.util.List;

import org.springframework.stereotype.Service;

@Service
public class RiskEngine {

    public ScanSummary calculateRisk(List<SecurityFinding> findings) {

        int passed = 0;
        int warnings = 0;
        int errors = 0;

        int highRisk = 0;
        int mediumRisk = 0;
        int lowRisk = 0;

        for (SecurityFinding finding : findings) {

            String status = finding.getStatus();
            String severity = finding.getSeverity();

            if ("PASS".equalsIgnoreCase(status)) {
                passed++;
            } else if ("WARNING".equalsIgnoreCase(status)) {
                warnings++;
            } else if ("ERROR".equalsIgnoreCase(status)) {
                errors++;
            }

            if ("HIGH".equalsIgnoreCase(severity)) {
                highRisk++;
            } else if ("MEDIUM".equalsIgnoreCase(severity)) {
                mediumRisk++;
            } else if ("LOW".equalsIgnoreCase(severity)) {
                lowRisk++;
            }
        }

        int score = 100;

        // Risk scoring:
        // HIGH   = -8 points
        // MEDIUM = -3 points
        // LOW    = -1 point
        // ERROR  = -8 points

        score -= highRisk * 8;
        score -= mediumRisk * 3;
        score -= lowRisk;
        score -= errors * 8;

        // Keep score between 0 and 100
        score = Math.max(0, Math.min(100, score));

        String riskLevel;

        if (errors > 0 || highRisk >= 3 || score < 50) {

            riskLevel = "HIGH";

        } else if (highRisk > 0 || mediumRisk >= 3 || score < 75) {

            riskLevel = "MEDIUM";

        } else if (mediumRisk > 0 || lowRisk > 0 || score < 90) {

            riskLevel = "LOW";

        } else {

            riskLevel = "SECURE";
        }

        return new ScanSummary(
                passed,
                warnings,
                errors,
                highRisk,
                mediumRisk,
                lowRisk,
                score,
                riskLevel
        );
    }
}

