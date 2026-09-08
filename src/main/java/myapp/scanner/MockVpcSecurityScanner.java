package myapp.scanner;

import myapp.model.SecurityFinding;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class MockVpcSecurityScanner implements SecurityScanner {

    @Override
    public List<SecurityFinding> scan(String region) {

        List<SecurityFinding> findings = new ArrayList<>();

        System.out.println();
        System.out.println("----------------------------------------");
        System.out.println("       VPC Security Checks");
        System.out.println("----------------------------------------");

        System.out.println(
                "Subnet: subnet-demo123"
                        + " | Public Route Detected [MEDIUM]"
        );

        findings.add(
                new SecurityFinding(
                        "CS-VPC-001",
                        "VPC Public Subnet - subnet-demo123",
                        "WARNING",
                        "MEDIUM",
                        "Subnet subnet-demo123 uses a route table with an active default route to an Internet Gateway.",
                        "Keep sensitive workloads in private subnets and expose only resources that require direct internet connectivity."
                )
        );

        findings.add(
    new SecurityFinding(
        "CS-VPC-002",
        "VPC Internet Gateway - igw-demo123",
        "INFO",
        "LOW",
        "VPC vpc-demo123 has an attached Internet Gateway igw-demo123, enabling internet connectivity.",
        "Verify that only intended public subnets and resources use internet-facing routes through this gateway."
    )
);

findings.add(
    new SecurityFinding(
        "CS-VPC-003",
        "VPC Default Security Group - sg-default123",
        "WARNING",
        "HIGH",
        "The default security group sg-default123 allows inbound traffic from the public internet.",
        "Remove public inbound rules from the default security group and use dedicated least-privilege security groups for workloads."
    )
);

findings.add(
    new SecurityFinding(
        "CS-VPC-004",
        "VPC Public Network ACL - acl-demo123",
        "WARNING",
        "HIGH",
        "Network ACL acl-demo123 allows inbound IPv4 traffic from 0.0.0.0/0.",
        "Restrict inbound Network ACL rules to trusted CIDR ranges and deny unnecessary internet access."
    )
);

findings.add(
    new SecurityFinding(
        "CS-VPC-005",
        "VPC Flow Logs",
        "WARNING",
        "MEDIUM",
        "No active VPC Flow Log configuration was detected.",
        "Enable VPC Flow Logs for critical VPCs to improve network visibility, investigation, and security monitoring."
    )
);

findings.add(
    new SecurityFinding(
        "CS-VPC-006",
        "VPC Public IPv6 Route - rtb-demo123",
        "WARNING",
        "HIGH",
        "Route table rtb-demo123 sends all IPv6 traffic (::/0) through Internet Gateway igw-demo123.",
        "Use IPv6 Internet Gateway routes only for intentionally public subnets and keep sensitive workloads on private or egress-only IPv6 paths."
    )
);
        return findings;
    }
}