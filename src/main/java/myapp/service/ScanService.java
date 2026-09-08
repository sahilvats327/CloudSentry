
package myapp.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import myapp.model.ScanSummary;
import myapp.model.SecurityFinding;
import myapp.scanner.Ec2SecurityScanner;
import myapp.scanner.IamSecurityScanner;
import myapp.scanner.MockIamSecurityScanner;
import myapp.scanner.S3SecurityScanner;
import org.springframework.stereotype.Service;
import myapp.scanner.MockS3SecurityScanner;
import myapp.scanner.MockEc2SecurityScanner;
import myapp.scanner.VpcSecurityScanner;
import myapp.scanner.MockVpcSecurityScanner;
import java.util.List;

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
        this.riskEngine = riskEngine;
        this.reportService = reportService;
    }

    public int scan(
        boolean security,
        String output,
        boolean s3,
        boolean iam,
        boolean ec2,
        boolean vpc,
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
                    new java.util.ArrayList<>();

            boolean targetedScan = s3 || iam || ec2 || vpc;

            if (targetedScan) {

                System.out.println();
                System.out.println("Targeted security scan: ENABLED");

                if (s3) {
    System.out.println("S3 scan: ENABLED");

    if (mock) {
        System.out.println("S3 scan mode: MOCK / OFFLINE");

        findings.addAll(
                mockS3SecurityScanner.scan(region)
        );
    } else {
        System.out.println("S3 scan mode: AWS");

        findings.addAll(
                s3SecurityScanner.scan(region)
        );
    }
}

                if (iam) {
    System.out.println("IAM scan: ENABLED");

    if (mock) {
        System.out.println("IAM scan mode: MOCK / OFFLINE");

        findings.addAll(
                mockIamSecurityScanner.scan(region)
        );
    } else {
        System.out.println("IAM scan mode: AWS");

        findings.addAll(
                iamSecurityScanner.scan(region)
        );
    }
}

                if (ec2) {
    System.out.println("EC2 scan: ENABLED");

    if (mock) {
        System.out.println("EC2 scan mode: MOCK / OFFLINE");

        findings.addAll(
                mockEc2SecurityScanner.scan(region)
        );
    } else {
        System.out.println("EC2 scan mode: AWS");

        findings.addAll(
                ec2SecurityScanner.scan(region)
        );
    }
}
if (vpc) {
    System.out.println("VPC scan: ENABLED");

    if (mock) {
        System.out.println("VPC scan mode: MOCK / OFFLINE");

        findings.addAll(
                mockVpcSecurityScanner.scan(region)
        );
    } else {
        System.out.println("VPC scan mode: AWS");

        findings.addAll(
                vpcSecurityScanner.scan(region)
        );
    }
}
} else {

    System.out.println();
    System.out.println("Full security scan: ENABLED");

    if (mock) {

        System.out.println("Full scan mode: MOCK / OFFLINE");

        findings.addAll(
                mockS3SecurityScanner.scan(region)
        );

        findings.addAll(
                mockIamSecurityScanner.scan(region)
        );

        findings.addAll(
                mockEc2SecurityScanner.scan(region)
        );
        findings.addAll(
                mockVpcSecurityScanner.scan(region)
);

    } else {

        System.out.println("Full scan mode: AWS");

        findings.addAll(
                s3SecurityScanner.scan(region)
        );

        findings.addAll(
                iamSecurityScanner.scan(region)
        );

        findings.addAll(
                ec2SecurityScanner.scan(region)
        );
        findings.addAll(
                vpcSecurityScanner.scan(region)
);
    }
}

      // Calculate the overall security risk from ALL findings
ScanSummary summary =
        calculateSummary(findings);

// Create a separate list for severity-filtered output
List<SecurityFinding> displayedFindings =
        new java.util.ArrayList<>(findings);

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

if (s3 || iam || ec2 || vpc) {

    StringBuilder targetBuilder = new StringBuilder();

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

    targets = targetBuilder.toString();

} else {

    targets = "S3, IAM, EC2, VPC";
}

reportService.exportJsonReport(
        output,
        region,
        targets,
        displayedFindings,
        summary,
        mock
);

            System.out.println();
            System.out.println("Scan completed.");

            // CLI exit codes:
            // 0 = SECURE / LOW
            // 1 = MEDIUM
            // 2 = HIGH

            if ("HIGH".equalsIgnoreCase(summary.getRiskLevel())) {
                return 2;
            }

            if ("MEDIUM".equalsIgnoreCase(summary.getRiskLevel())) {
                return 1;
            }

            return 0;
        }

        System.out.println();
        System.out.println("Scan completed.");

        return 0;
    }

    

    private ScanSummary calculateSummary(
            List<SecurityFinding> findings) {

        
return riskEngine.calculateRisk(findings);


    }

}
   

