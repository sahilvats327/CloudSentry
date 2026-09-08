package myapp.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import myapp.model.ScanSummary;
import myapp.model.SecurityFinding;
import myapp.model.SecurityReport;
import org.springframework.stereotype.Service;

import java.io.File;
import java.time.Instant;
import java.util.List;

@Service
public class ReportService {

    private final ObjectMapper objectMapper;

    public ReportService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

   public void displayFindings(
        List<SecurityFinding> findings,
        String region,
        boolean mock,
        int overallFindingCount) {

    System.out.println();
    System.out.println("========================================");
    System.out.println("       CloudSentry Security Report");
    System.out.println("========================================");

    System.out.println();
    System.out.println("Scan Mode:       " + (mock ? "MOCK / OFFLINE" : "AWS"));
    System.out.println("Region:          " + region);
    System.out.println("Timestamp:       " + Instant.now());
    System.out.println("Overall Findings:    " + overallFindingCount);
    System.out.println("Displayed Findings:  " + findings.size());

    for (SecurityFinding finding : findings) {

        System.out.println();

        System.out.println(
                "[" + finding.getSeverity() + "] "
                        + finding.getId()
        );

        System.out.println(
                "Check:           " + finding.getCheck()
        );

        System.out.println(
                "Status:          " + finding.getStatus()
        );

        System.out.println(
                "Issue:           " + finding.getMessage()
        );

        System.out.println(
                "Recommendation:  " + finding.getRecommendation()
        );

        System.out.println("----------------------------------------");
    }
}

    public void displaySummary(ScanSummary summary) {

        System.out.println();
        System.out.println("========================================");
        System.out.println("          CloudSentry Summary");
        System.out.println("========================================");

        System.out.println(
                "Passed:    " + summary.getPassed()
        );

        System.out.println(
                "Warnings:  " + summary.getWarnings()
        );

        System.out.println(
                "Errors:    " + summary.getErrors()
        );

        System.out.println();

        System.out.println(
                "High Risk Findings:   "
                        + summary.getHighRisk()
        );

        System.out.println(
                "Medium Risk Findings: "
                        + summary.getMediumRisk()
        );

        System.out.println(
                "Low Risk Findings:    "
                        + summary.getLowRisk()
        );

        System.out.println();

        System.out.println(
                "Security Score: "
                        + summary.getSecurityScore()
                        + "/100"
        );

        System.out.println(
                "Risk Level: "
                        + summary.getRiskLevel()
        );
    }

    public void exportJsonReport(
        String output,
        String region,
        String targets,
        List<SecurityFinding> findings,
        ScanSummary summary,
        boolean mock
) {

        try {

            SecurityReport report = new SecurityReport(
        "CloudSentry",
        region,
        mock ? "MOCK" : "AWS",
        targets,
        Instant.now().toString(),
                    findings.size(),
                    summary.getPassed(),
                    summary.getWarnings(),
                    summary.getErrors(),
                    summary.getHighRisk(),
                    summary.getMediumRisk(),
                    summary.getLowRisk(),
                    summary.getSecurityScore(),
                    summary.getRiskLevel(),
                    findings
            );

            objectMapper
                    .writerWithDefaultPrettyPrinter()
                    .writeValue(
                            new File(output),
                            report
                    );

            System.out.println();
            System.out.println(
                    "JSON report exported: " + output
            );

        } catch (Exception e) {

            System.out.println();
            System.out.println(
                    "JSON report export failed."
            );

            System.out.println(
                    "Reason: " + e.getMessage()
            );
        }
    }
}