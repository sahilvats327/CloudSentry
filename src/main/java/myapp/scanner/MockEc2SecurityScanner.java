package myapp.scanner;

import myapp.model.SecurityFinding;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class MockEc2SecurityScanner implements SecurityScanner {

    @Override
    public List<SecurityFinding> scan(String region) {

        List<SecurityFinding> findings = new ArrayList<>();

        // =========================================================
        // CS-EC2-001 — Security Group Exposure
        // =========================================================

        findings.add(new SecurityFinding(
                "CS-EC2-001",
                "EC2 Security Group Public Access",
                "WARNING",
                "HIGH",
                "Security group allows SSH access from the public internet.",
                "Restrict SSH access to trusted IP addresses or trusted network ranges."
        ));

        // =========================================================
        // CS-EC2-002 — EBS Encryption
        // =========================================================

        findings.add(new SecurityFinding(
                "CS-EC2-002",
                "EC2 EBS Encryption - vol-demo123",
                "PASS",
                "NONE",
                "EBS volume vol-demo123 is encrypted.",
                "No action required. Continue using encryption for EBS volumes."
        ));

        // =========================================================
        // CS-EC2-003 — Public IP Exposure
        // =========================================================

        findings.add(new SecurityFinding(
                "CS-EC2-003",
                "EC2 Public IP Exposure - i-demo123",
                "WARNING",
                "MEDIUM",
                "EC2 instance i-demo123 has a public IPv4 address: 203.0.113.10",
                "Remove unnecessary public IP exposure and use private networking where possible."
        ));

        // =========================================================
        // CS-EC2-004 — IMDSv2 Enforcement
        // =========================================================

        findings.add(new SecurityFinding(
                "CS-EC2-004",
                "EC2 IMDS Security - i-demo123",
                "WARNING",
                "MEDIUM",
                "IMDSv2 is not required for EC2 instance i-demo123.",
                "Configure the instance metadata service to require IMDSv2."
        ));

        // =========================================================
        // CS-EC2-005 — Termination Protection
        // =========================================================

        findings.add(new SecurityFinding(
                "CS-EC2-005",
                "EC2 Termination Protection - i-demo123",
                "INFO",
                "LOW",
                "API termination protection is not enabled for EC2 instance i-demo123.",
                "Consider enabling termination protection for important production instances."
        ));

        findings.add(
    new SecurityFinding(
        "CS-EC2-006",
        "EC2 Public EBS Snapshot - snap-0123456789abcdef0",
        "WARNING",
        "HIGH",
        "An EBS snapshot is publicly restorable.",
        "Remove public access from the snapshot unless public sharing is explicitly required."
    )
);
findings.add(
    new SecurityFinding(
        "CS-EC2-007",
        "EC2 Unencrypted EBS Snapshot - snap-0987654321abcdef0",
        "WARNING",
        "MEDIUM",
        "An EBS snapshot is not encrypted.",
        "Use encrypted EBS snapshots to protect stored data and reduce the risk of unauthorized data exposure."
    )
);

findings.add(
    new SecurityFinding(
        "CS-EC2-008",
        "EC2 Public Sensitive Port - sg-demo123:3389",
        "WARNING",
        "HIGH",
        "RDP port 3389 is publicly accessible from 0.0.0.0/0.",
        "Restrict RDP access to trusted IP ranges or private networks and avoid exposing sensitive services directly to the internet."
    )
);
findings.add(
    new SecurityFinding(
        "CS-EC2-009",
        "EC2 Unrestricted Outbound Traffic - sg-demo123",
        "WARNING",
        "LOW",
        "Security group sg-demo123 allows outbound traffic to 0.0.0.0/0.",
        "Restrict outbound traffic to only the destinations and protocols required by the workload."
    )
);

findings.add(
    new SecurityFinding(
        "CS-EC2-010",
        "EC2 Public IPv6 Access - sg-demo123",
        "WARNING",
        "HIGH",
        "Security group sg-demo123 allows inbound IPv6 traffic from the entire internet (::/0).",
        "Restrict IPv6 access to trusted IPv6 CIDR ranges and expose only the ports required by the workload."
    )
);

findings.add(
    new SecurityFinding(
        "CS-EC2-011",
        "EC2 Public AMI - ami-0123456789abcdef0",
        "WARNING",
        "HIGH",
        "AMI ami-0123456789abcdef0 is publicly accessible and can be launched by other AWS users.",
        "Remove public sharing from the AMI unless public distribution is explicitly required."
    )
);

findings.add(
    new SecurityFinding(
        "CS-EC2-012",
        "EC2 Unencrypted EBS Volume - vol-demo456",
        "WARNING",
        "HIGH",
        "EBS volume vol-demo456 is not encrypted.",
        "Enable encryption for the EBS volume and use encrypted volumes for sensitive workloads."
    )
);
        return findings;
    }
}