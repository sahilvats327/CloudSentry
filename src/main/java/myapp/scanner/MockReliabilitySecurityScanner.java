package myapp.scanner;

import myapp.model.SecurityFinding;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class MockReliabilitySecurityScanner {

    public List<SecurityFinding> scan(String region) {

        List<SecurityFinding> findings = new ArrayList<>();

        System.out.println();
        System.out.println("========================================");
        System.out.println("       MOCK RELIABILITY SCAN");
        System.out.println("========================================");

findings.add(
        new SecurityFinding(
                "CS-REL-001",
                "RDS Multi-AZ Disabled - mock-db-01",
                "WARNING",
                "MEDIUM",
                "RDS instance mock-db-01 does not have Multi-AZ deployment enabled.",
                "Enable Multi-AZ deployment for production RDS workloads that require high availability."
        )
);

findings.add(
        new SecurityFinding(
                "CS-REL-002",
                "S3 Lifecycle Policy Missing - mock-bucket-01",
                "WARNING",
                "MEDIUM",
                "S3 bucket mock-bucket-01 does not have a lifecycle policy configured.",
                "Configure an appropriate S3 lifecycle policy to manage object retention and storage costs."
        )
);

findings.add(
        new SecurityFinding(
                "CS-REL-003",
                "EC2 Instance Not in Auto Scaling Group - i-0mock123456789",
                "WARNING",
                "MEDIUM",
                "EC2 instance i-0mock123456789 is not currently a member of an Auto Scaling Group.",
                "For workloads requiring high availability and automatic recovery, consider placing the instance in an appropriate Auto Scaling Group."
        )
);

return findings;
    }
}