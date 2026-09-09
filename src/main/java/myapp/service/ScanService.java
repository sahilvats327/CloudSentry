package myapp.service;

import myapp.model.ScanSummary;
import myapp.model.SecurityFinding;
import myapp.scanner.CostSecurityScanner;
import myapp.scanner.Ec2SecurityScanner;
import myapp.scanner.IamSecurityScanner;
import myapp.scanner.MockCostSecurityScanner;
import myapp.scanner.MockEc2SecurityScanner;
import myapp.scanner.MockIamSecurityScanner;
import myapp.scanner.MockS3SecurityScanner;
import myapp.scanner.MockVpcSecurityScanner;
import myapp.scanner.S3SecurityScanner;
import myapp.scanner.VpcSecurityScanner;



import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

@Service
public class ScanService {

    private final IamSecurityScanner iamSecurityScanner;
    private final MockIamSecurityScanner mockIamSecurityScanner;
    private final AwsIdentityService awsIdentityService;
    private final S3SecurityScanner s3SecurityScanner;
    private final MockS3SecurityScanner mockS3SecurityScanner;
    private final Ec2SecurityScanner ec2SecurityScanner;
    private final MockEc2SecurityScanner mockEc2SecurityScanner;
    private final VpcSecurityScanner vpcSecurityScanner;
    private final MockVpcSecurityScanner mockVpcSecurityScanner;
    private final CostSecurityScanner costSecurityScanner;
    private final MockCostSecurityScanner mockCostSecurityScanner;
    private final RiskEngine riskEngine;
    private final ReportService reportService;

    public ScanService(
            AwsIdentityService awsIdentityService,
            S3SecurityScanner s3SecurityScanner,
            MockS3SecurityScanner mockS3SecurityScanner,
            IamSecurityScanner iamSecurityScanner,
            MockIamSecurityScanner mockIamSecurityScanner,
            Ec2SecurityScanner ec2SecurityScanner,
            MockEc2SecurityScanner mockEc2SecurityScanner,
            VpcSecurityScanner vpcSecurityScanner,
            MockVpcSecurityScanner mockVpcSecurityScanner,
            CostSecurityScanner costSecurityScanner,
            MockCostSecurityScanner mockCostSecurityScanner,
            RiskEngine riskEngine,
            ReportService reportService
    ) {

        this.awsIdentityService = awsIdentityService;
        this.s3SecurityScanner = s3SecurityScanner;
        this.mockS3SecurityScanner = mockS3SecurityScanner;
        this.iamSecurityScanner = iamSecurityScanner;
        this.mockIamSecurityScanner = mockIamSecurityScanner;
        this.ec2SecurityScanner = ec2SecurityScanner;
        this.mockEc2SecurityScanner = mockEc2SecurityScanner;
        this.vpcSecurityScanner = vpcSecurityScanner;
        this.mockVpcSecurityScanner = mockVpcSecurityScanner;
        this.costSecurityScanner = costSecurityScanner;
        this.mockCostSecurityScanner = mockCostSecurityScanner;
        this.riskEngine = riskEngine;
        this.reportService = reportService;
    }

    public Integer scan(
        boolean security,
        String output,
        boolean s3,
        boolean iam,
        boolean ec2,
        boolean vpc,
        boolean cost,
        String region,
        boolean mock,
        String severity) {

        System.out.println("CloudSentry scan started.");

        if (security) {
            System.out.println("Security checks: ENABLED");
        } else {
            System.out.println("Security checks: DISABLED");
        }

        if (mock) {

            System.out.println("Scan mode: MOCK / OFFLINE");

        } else {

            System.out.println("Scan mode: AWS");

            boolean awsConnected =
                    awsIdentityService.checkIdentity();

            if (!awsConnected) {

                System.out.println();
                System.out.println("AWS authentication failed.");
                System.out.println("Scan aborted.");

                return 3;
            }
        }

        if (security) {

            List<SecurityFinding> findings =
                    new ArrayList<>();

            boolean targetedScan =
        s3 || iam || ec2 || vpc || cost;

            if (targetedScan) {

                System.out.println();
                System.out.println("Targeted security scan: ENABLED");

                if (s3) {

                    System.out.println("S3 scan: ENABLED");

                    findings.addAll(
                            runScanner(
                                    "S3",
                                    mock,
                                    s3SecurityScanner::scan,
                                    mockS3SecurityScanner::scan,
                                    region
                            )
                    );
                }

                if (iam) {

                    System.out.println("IAM scan: ENABLED");

                    findings.addAll(
                            runScanner(
                                    "IAM",
                                    mock,
                                    iamSecurityScanner::scan,
                                    mockIamSecurityScanner::scan,
                                    region
                            )
                    );
                }

                if (ec2) {

                    System.out.println("EC2 scan: ENABLED");

                    findings.addAll(
                            runScanner(
                                    "EC2",
                                    mock,
                                    ec2SecurityScanner::scan,
                                    mockEc2SecurityScanner::scan,
                                    region
                            )
                    );
                }

                if (vpc) {

                    System.out.println("VPC scan: ENABLED");

                    findings.addAll(
                            runScanner(
                                    "VPC",
                                    mock,
                                    vpcSecurityScanner::scan,
                                    mockVpcSecurityScanner::scan,
                                    region
                            )
                    );
                }
                if (cost) {
    System.out.println("COST scan: ENABLED");

    findings.addAll(
            runScanner(
                    "COST",
                    mock,
                    costSecurityScanner::scan,
                    mockCostSecurityScanner::scan,
                    region
            )
    );
}

            } else {

                System.out.println();
                System.out.println("Full security scan: ENABLED");

                System.out.println(
                        "Full scan mode: "
                                + (mock
                                ? "MOCK / OFFLINE"
                                : "AWS")
                );

                findings.addAll(
                        runScanner(
                                "S3",
                                mock,
                                s3SecurityScanner::scan,
                                mockS3SecurityScanner::scan,
                                region
                        )
                );

                findings.addAll(
                        runScanner(
                                "IAM",
                                mock,
                                iamSecurityScanner::scan,
                                mockIamSecurityScanner::scan,
                                region
                        )
                );

                findings.addAll(
                        runScanner(
                                "EC2",
                                mock,
                                ec2SecurityScanner::scan,
                                mockEc2SecurityScanner::scan,
                                region
                        )
                );

                findings.addAll(
                        runScanner(
                                "VPC",
                                mock,
                                vpcSecurityScanner::scan,
                                mockVpcSecurityScanner::scan,
                                region
                        )
                );

                findings.addAll(
        runScanner(
                "COST",
                mock,
                costSecurityScanner::scan,
                mockCostSecurityScanner::scan,
                region
        )
);
            }

            // Calculate the overall security risk from ALL findings
            ScanSummary summary =
                    calculateSummary(findings);

            // Create a separate list for severity-filtered output
            List<SecurityFinding> displayedFindings =
                    new ArrayList<>(findings);

            if (!"ALL".equalsIgnoreCase(severity)) {

                displayedFindings.removeIf(
                        finding -> !severity.equalsIgnoreCase(
                                finding.getSeverity()
                        )
                );
            }

            reportService.displayFindings(
                    displayedFindings,
                    region,
                    mock,
                    findings.size()
            );

            reportService.displaySummary(summary);

            String targets;

            if (s3 || iam || ec2 || vpc || cost) {

                StringBuilder targetBuilder =
                        new StringBuilder();

                if (s3) {
                    targetBuilder.append("S3");
                }

                if (iam) {

                    if (targetBuilder.length() > 0) {
                        targetBuilder.append(", ");
                    }

                    targetBuilder.append("IAM");
                }

                if (ec2) {

                    if (targetBuilder.length() > 0) {
                        targetBuilder.append(", ");
                    }

                    targetBuilder.append("EC2");
                }

                if (vpc) {

                    if (targetBuilder.length() > 0) {
                        targetBuilder.append(", ");
                    }

                    targetBuilder.append("VPC");
                }

                if (cost) {

    if (targetBuilder.length() > 0) {
        targetBuilder.append(", ");
    }

    targetBuilder.append("COST");
}

                targets = targetBuilder.toString();

            } else {

                targets = "S3, IAM, EC2, VPC, COST";
            }

            reportService.exportJsonReport(
                    output,
                    region,
                    targets,
                    displayedFindings,
                    summary,
                    mock,
                    findings.size()
            );

            reportService.exportHtmlReport(
                    "cloudsentry-report.html",
                    region,
                    targets,
                    displayedFindings,
                    summary,
                    mock,
                    findings.size()
            );

            System.out.println();
            System.out.println("Scan completed.");

            // CLI exit codes:
            // 0 = Scan completed successfully with LOW/no risk
            // 1 = MEDIUM security risk detected
            // 2 = HIGH security risk detected
            // 3 = AWS authentication failure
            // 4 = Invalid scan configuration
            // 5 = Invalid severity value

            if ("HIGH".equalsIgnoreCase(
                    summary.getRiskLevel())) {

                return 2;
            }

            if ("MEDIUM".equalsIgnoreCase(
                    summary.getRiskLevel())) {

                return 1;
            }

            return 0;
        }

        System.out.println();
        System.out.println("Scan completed.");

        return 0;
    }

    /**
     * Runs either the real AWS scanner or the mock scanner
     * depending on the selected scan mode.
     */
    private List<SecurityFinding> runScanner(
            String scannerName,
            boolean mock,
            Function<String, List<SecurityFinding>> realScanner,
            Function<String, List<SecurityFinding>> mockScanner,
            String region) {

        System.out.println(
                scannerName + " scan mode: "
                        + (mock
                        ? "MOCK / OFFLINE"
                        : "AWS")
        );

        Function<String, List<SecurityFinding>> scanner =
                mock ? mockScanner : realScanner;

        return scanner.apply(region);
    }

    private ScanSummary calculateSummary(
            List<SecurityFinding> findings) {

        return riskEngine.calculateRisk(findings);
    }
}