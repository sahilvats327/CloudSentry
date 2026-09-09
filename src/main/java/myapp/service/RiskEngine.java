
package myapp.service;

import myapp.model.ScanSummary;
import myapp.model.SecurityFinding;

import java.util.List;

import org.springframework.stereotype.Service;

@Service
public class RiskEngine {

    public ScanSummary calculateRisk(List<SecurityFinding> findings) {

       int passed = 0;
       int informational = 0;
       int warnings = 0;
       int errors = 0;
        int highRisk = 0;
        int mediumRisk = 0;
        int lowRisk = 0;

        for (SecurityFinding finding : findings) {

            String status = finding.getStatus();
            String severity = finding.getSeverity();

            // Count statuses
            if ("PASS".equalsIgnoreCase(status)) {
    passed++;

} else if ("WARNING".equalsIgnoreCase(status)) {
    warnings++;

} else if ("ERROR".equalsIgnoreCase(status)) {
    errors++;

} else if ("INFO".equalsIgnoreCase(status)) {
    informational++;
}

            // Count severity
            if ("HIGH".equalsIgnoreCase(severity)) {
                highRisk++;
            } else if ("MEDIUM".equalsIgnoreCase(severity)) {
                mediumRisk++;
            } else if ("LOW".equalsIgnoreCase(severity)) {
                lowRisk++;
            }
        }

        /*
         * ---------------------------------------------------------
         * NORMALIZED SECURITY SCORE
         * ---------------------------------------------------------
         *
         * Each finding receives a risk weight:
         *
         * HIGH   = 3 points
         * MEDIUM = 2 points
         * LOW    = 1 point
         *
         * The score is calculated relative to the total number
         * of findings, so scanning more AWS services does not
         * automatically force the score to 0.
         */

        int totalFindings = findings.size();

        int riskPoints =
                (highRisk * 3)
                + (mediumRisk * 2)
                + lowRisk;

        int maximumRiskPoints = totalFindings * 3;

        int score;

        if (totalFindings == 0) {

            // No findings means there is nothing to evaluate.
            score = 100;

        } else {

            double riskPercentage =
                    (double) riskPoints / maximumRiskPoints;

            score = (int) Math.round(
                    100 - (riskPercentage * 100)
            );
        }

        /*
         * Errors represent serious operational/security problems.
         * Apply an additional penalty while keeping the score
         * within the 0-100 range.
         */
        score -= errors * 5;

        // Keep score between 0 and 100
        score = Math.max(0, Math.min(100, score));

        /*
         * ---------------------------------------------------------
         * RISK LEVEL
         * ---------------------------------------------------------
         */

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
        informational,
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

