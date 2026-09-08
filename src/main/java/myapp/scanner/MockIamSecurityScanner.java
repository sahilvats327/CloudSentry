package myapp.scanner;

import myapp.model.SecurityFinding;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class MockIamSecurityScanner implements SecurityScanner {

    @Override
    public List<SecurityFinding> scan(String region) {

        List<SecurityFinding> findings = new ArrayList<>();

        // Simulated root account checks
        findings.add(new SecurityFinding(
                "CS-IAM-001",
                "IAM Root Account MFA",
                "WARNING",
                "HIGH",
                "Root account does not have MFA enabled.",
                "Enable MFA on the AWS root account."
        ));

        findings.add(new SecurityFinding(
                "CS-IAM-002",
                "IAM Root Access Keys",
                "PASS",
                "NONE",
                "No root account access keys detected.",
                "No action required."
        ));

        // Simulated IAM user
        String user = "demo-user";

        findings.add(new SecurityFinding(
                "CS-IAM-003",
                "IAM MFA - " + user,
                "WARNING",
                "MEDIUM",
                "IAM user does not have MFA enabled.",
                "Enable MFA for the IAM user."
        ));

        findings.add(new SecurityFinding(
                "CS-IAM-004",
                "IAM Access Key Age - " + user,
                "WARNING",
                "MEDIUM",
                "Access key is older than 90 days.",
                "Rotate the access key."
        ));

        findings.add(new SecurityFinding(
                "CS-IAM-005",
                "IAM Access Key Usage - " + user,
                "PASS",
                "NONE",
                "Access key has been used recently.",
                "No action required."
        ));

        // Simulated dangerous inline policy
        findings.add(new SecurityFinding(
                "CS-IAM-006",
                "IAM Inline Policy Analysis - " + user,
                "WARNING",
                "HIGH",
                "Inline policy contains unrestricted permissions.",
                "Restrict actions and resources to only what is required."
        ));

        // Simulated dangerous managed policy
        findings.add(new SecurityFinding(
                "CS-IAM-007",
                "IAM Policy Analysis - " + user,
                "WARNING",
                "HIGH",
                "Attached policy contains wildcard permissions.",
                "Replace wildcard permissions with least-privilege permissions."
        ));
              

        findings.add(new SecurityFinding(
                "CS-IAM-008",
                "IAM Group Policies - " + user,
                "PASS",
                "NONE",
                "No dangerous group policy permissions detected.",
                "No action required."
        ));

        findings.add(new SecurityFinding(
                "CS-IAM-009",
                "IAM Password Policy",
                "WARNING",
                "MEDIUM",
                "Password policy does not meet the recommended security requirements.",
                "Configure a strong IAM password policy."
        ));
        
        // Simulated AdministratorAccess policy
        findings.add(new SecurityFinding(
                "CS-IAM-010",
                "IAM AdministratorAccess - " + user,
                "WARNING",
                "HIGH",
                "IAM user has the AWS-managed AdministratorAccess policy attached.",
                "Remove AdministratorAccess and replace it with a least-privilege policy containing only the permissions required."
        ));
                // Simulated multiple active access keys
        findings.add(new SecurityFinding(
                "CS-IAM-011",
                "IAM Multiple Active Access Keys - " + user,
                "WARNING",
                "MEDIUM",
                "IAM user has multiple active access keys.",
                "Remove unused access keys and keep only the credentials required for the user's workload."
        ));
        // Simulated inactive access key
findings.add(new SecurityFinding(
        "CS-IAM-012",
        "IAM Inactive Access Key - " + user,
        "WARNING",
        "MEDIUM",
        "IAM user has an inactive access key.",
        "Remove inactive access keys when they are no longer required."
));

// Simulated privilege escalation risk
findings.add(new SecurityFinding(
        "CS-IAM-013",
        "IAM Privilege Escalation Risk - " + user,
        "WARNING",
        "HIGH",
        "IAM policy contains a privilege-sensitive action such as iam:PassRole.",
        "Restrict privilege-sensitive IAM actions to only the identities and resources that require them."
));
        return findings;
    }
}