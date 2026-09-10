package myapp.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import myapp.model.ScanSummary;
import myapp.model.SecurityFinding;
import myapp.model.SecurityReport;

import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class ReportService {

    private final ObjectMapper objectMapper;
    private final SpringTemplateEngine templateEngine;

    public ReportService(
            ObjectMapper objectMapper,
            SpringTemplateEngine templateEngine) {

        this.objectMapper = objectMapper;
        this.templateEngine = templateEngine;
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
        System.out.println(
                "Scan Mode:           "
                        + (mock ? "MOCK / OFFLINE" : "AWS")
        );

        System.out.println(
                "Region:              " + region
        );

        System.out.println(
                "Timestamp:           " + Instant.now()
        );

        System.out.println(
                "Overall Findings:    " + overallFindingCount
        );

        System.out.println(
                "Displayed Findings:  " + findings.size()
        );

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
        "Passed:          " + summary.getPassed()
);

System.out.println(
        "Informational:   " + summary.getInformational()
);

System.out.println(
        "Warnings:        " + summary.getWarnings()
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
            boolean mock,
            int overallFindingCount) {

        try {

            SecurityReport report = new SecurityReport(
                    "CloudSentry",
                    region,
                    mock ? "MOCK" : "AWS",
                    targets,
                    Instant.now().toString(),
                    overallFindingCount,
                    summary.getPassed(),
                    summary.getInformational(),
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

    public void exportHtmlReport(
            String output,
            String region,
            String targets,
            List<SecurityFinding> findings,
            ScanSummary summary,
            boolean mock,
            int overallFindingCount) {

        try {

            Context context = new Context();

            /*
             * Basic scan information
             */
            context.setVariable(
                    "applicationName",
                    "CloudSentry"
            );

            context.setVariable(
                    "region",
                    region
            );

            context.setVariable(
                    "targets",
                    targets
            );

            context.setVariable(
                    "mode",
                    mock ? "MOCK / OFFLINE" : "AWS"
            );

            context.setVariable(
                    "timestamp",
                    Instant.now()
            );

            context.setVariable(
                    "overallFindingCount",
                    overallFindingCount
            );

            /*
             * Existing models
             */
            context.setVariable(
                    "findings",
                    findings
            );

            context.setVariable(
                    "summary",
                    summary
            );

            /*
             * Executive summary
             */
            context.setVariable(
                    "highCount",
                    summary.getHighRisk()
            );

            context.setVariable(
                    "mediumCount",
                    summary.getMediumRisk()
            );

            context.setVariable(
                    "lowCount",
                    summary.getLowRisk()
            );

            context.setVariable(
                    "passCount",
                    summary.getPassed()
            );

            /*
             * Findings grouped by severity
             */
            Map<String, List<SecurityFinding>> findingsBySeverity =
                    new LinkedHashMap<>();

            findingsBySeverity.put(
                    "HIGH",
                    findings.stream()
                            .filter(f ->
                                    "HIGH".equalsIgnoreCase(
                                            f.getSeverity()
                                    )
                            )
                            .toList()
            );

            findingsBySeverity.put(
                    "MEDIUM",
                    findings.stream()
                            .filter(f ->
                                    "MEDIUM".equalsIgnoreCase(
                                            f.getSeverity()
                                    )
                            )
                            .toList()
            );

            findingsBySeverity.put(
                    "LOW",
                    findings.stream()
                            .filter(f ->
                                    "LOW".equalsIgnoreCase(
                                            f.getSeverity()
                                    )
                            )
                            .toList()
            );

            findingsBySeverity.put(
                    "PASS",
                    findings.stream()
                            .filter(f ->
                                    "PASS".equalsIgnoreCase(
                                            f.getStatus()
                                    )
                                            || "PASS".equalsIgnoreCase(
                                            f.getSeverity()
                                    )
                            )
                            .toList()
            );

            context.setVariable(
                    "findingsBySeverity",
                    findingsBySeverity
            );

            /*
             * Service breakdown
             *
             * Rule ID format:
             *
             * CS-S3-xxx
             * CS-IAM-xxx
             * CS-EC2-xxx
             * CS-VPC-xxx
             * CS-COST-xxx
             */
            Map<String, Long> serviceCounts =
                    new LinkedHashMap<>();

            serviceCounts.put(
                    "S3",
                    findings.stream()
                            .filter(f ->
                                    f.getId() != null
                                            && f.getId()
                                            .startsWith("CS-S3-")
                            )
                            .count()
            );

            serviceCounts.put(
                    "IAM",
                    findings.stream()
                            .filter(f ->
                                    f.getId() != null
                                            && f.getId()
                                            .startsWith("CS-IAM-")
                            )
                            .count()
            );

            serviceCounts.put(
                    "EC2",
                    findings.stream()
                            .filter(f ->
                                    f.getId() != null
                                            && f.getId()
                                            .startsWith("CS-EC2-")
                            )
                            .count()
            );

           serviceCounts.put(
        "VPC",
        findings.stream()
                .filter(f ->
                        f.getId() != null
                                && f.getId()
                                .startsWith("CS-VPC-")
                )
                .count()
);

serviceCounts.put(
        "COST",
        findings.stream()
                .filter(f ->
                        f.getId() != null
                                && f.getId()
                                .startsWith("CS-COST-")
                )
                .count()
);

serviceCounts.put(
        "RELIABILITY",
        findings.stream()
                .filter(f ->
                        f.getId() != null
                                && f.getId()
                                .startsWith("CS-REL-")
                )
                .count()
);

context.setVariable(
        "serviceCounts",
        serviceCounts
);

            /*
             * Render Thymeleaf template
             */
            String html = templateEngine.process(
                    "security-report",
                    context
            );

            /*
             * Write HTML report
             */
            File outputFile = new File(output);

            Files.writeString(
                    outputFile.toPath(),
                    html,
                    StandardCharsets.UTF_8
            );

            System.out.println();
            System.out.println(
                    "HTML report exported: " + output
            );

        } catch (Exception e) {

            System.out.println();
            System.out.println(
                    "HTML report export failed."
            );

            System.out.println(
                    "Reason: " + e.getMessage()
            );
        }
    }
}