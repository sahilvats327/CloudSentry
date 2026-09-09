package myapp.scanner;

import myapp.model.SecurityFinding;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class MockCostSecurityScanner {

    public List<SecurityFinding> scan(String region) {

        List<SecurityFinding> findings = new ArrayList<>();

        System.out.println();
        System.out.println("========================================");
        System.out.println("       COST OPTIMIZATION SCAN");
        System.out.println("========================================");

        System.out.println();
        System.out.println("----------------------------------------");
        System.out.println("       Unattached EBS Volumes");
        System.out.println("----------------------------------------");

        System.out.println(
                "Volume: vol-demo123 | State: available | UNATTACHED [MEDIUM]"
        );

        findings.add(
                new SecurityFinding(
                        "CS-COST-001",
                        "Unattached EBS Volume - vol-demo123",
                        "WARNING",
                        "MEDIUM",
                        "EBS volume vol-demo123 is not attached to any EC2 instance and may continue generating storage costs.",
                        "Review the volume and delete it if it is no longer required. Create a snapshot first if the data must be retained."
                )
        );

        System.out.println(
                "Volume: vol-demo456 | State: in-use | ATTACHED [PASS]"
        );

        findings.add(
                new SecurityFinding(
                        "CS-COST-001",
                        "EBS Volume - vol-demo456",
                        "PASS",
                        "NONE",
                        "EBS volume vol-demo456 is attached to an EC2 instance.",
                        "No action required."
                )
        );

        System.out.println();
System.out.println("----------------------------------------");
System.out.println("          Elastic IP Checks");
System.out.println("----------------------------------------");

System.out.println(
        "Elastic IP: 203.0.113.10 | NOT ASSOCIATED [MEDIUM]"
);

findings.add(
        new SecurityFinding(
                "CS-COST-002",
                "Unused Elastic IP - 203.0.113.10",
                "WARNING",
                "MEDIUM",
                "Elastic IP 203.0.113.10 is not associated with an EC2 instance and may generate unnecessary AWS charges.",
                "Release the Elastic IP if it is no longer required."
        )
);

System.out.println(
        "Elastic IP: 203.0.113.20 | Instance: i-demo123 [PASS]"
);

findings.add(
        new SecurityFinding(
                "CS-COST-002",
                "Elastic IP - 203.0.113.20",
                "PASS",
                "NONE",
                "Elastic IP 203.0.113.20 is associated with running EC2 instance i-demo123.",
                "No action required."
        )
);

System.out.println(
        "Elastic IP: 203.0.113.30 | Instance: i-demo456 | INSTANCE STOPPED [MEDIUM]"
);

findings.add(
        new SecurityFinding(
                "CS-COST-002",
                "Elastic IP on Stopped Instance - 203.0.113.30",
                "WARNING",
                "MEDIUM",
                "Elastic IP 203.0.113.30 is associated with stopped EC2 instance i-demo456 and may be generating unnecessary AWS charges.",
                "Review whether the stopped instance and its Elastic IP are still required. Release the Elastic IP if it is no longer needed."
        )
);
        System.out.println();
        System.out.println("----------------------------------------");
        System.out.println("       Long-Stopped EC2 Instances");
        System.out.println("----------------------------------------");

        System.out.println(
                "Instance: i-demo456 | Stopped: 47 days | EXTENDED [MEDIUM]"
        );

        findings.add(
                new SecurityFinding(
                        "CS-COST-003",
                        "Long-Stopped EC2 Instance - i-demo456",
                        "WARNING",
                        "MEDIUM",
                        "EC2 instance i-demo456 has remained stopped for approximately 47 days.",
                        "Review the instance and terminate it if it is no longer required. Preserve required data or AMIs before termination."
                )
        );

        System.out.println(
                "Instance: i-demo789 | Stopped: 8 days [PASS]"
        );

        findings.add(
                new SecurityFinding(
                        "CS-COST-003",
                        "Stopped EC2 Instance - i-demo789",
                        "PASS",
                        "NONE",
                        "EC2 instance i-demo789 has been stopped for approximately 8 days, which is below the configured threshold of 30 days.",
                        "No action required."
                )
        );

        return findings;
    }
}