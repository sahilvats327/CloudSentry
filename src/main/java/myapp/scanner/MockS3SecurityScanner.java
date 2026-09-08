package myapp.scanner;

import myapp.model.SecurityFinding;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class MockS3SecurityScanner implements SecurityScanner {

    @Override
    public List<SecurityFinding> scan(String region) {

        List<SecurityFinding> findings = new ArrayList<>();

        // Simulated public bucket check
        findings.add(new SecurityFinding(
                "CS-S3-001",
                "S3 Bucket Public Access",
                "WARNING",
                "HIGH",
                "Bucket demo-public-bucket allows public access.",
                "Block public access unless explicitly required."
        ));

        // Simulated bucket encryption check
        findings.add(new SecurityFinding(
                "CS-S3-002",
                "S3 Bucket Encryption",
                "PASS",
                "NONE",
                "Bucket demo-secure-bucket has server-side encryption enabled.",
                "No action required."
        ));

        // Simulated bucket versioning check
        findings.add(new SecurityFinding(
                "CS-S3-003",
                "S3 Bucket Versioning",
                "WARNING",
                "MEDIUM",
                "Bucket demo-data-bucket does not have versioning enabled.",
                "Enable S3 bucket versioning to improve data recovery."
        ));

        // Simulated logging check
        findings.add(new SecurityFinding(
                "CS-S3-004",
                "S3 Bucket Logging",
                "WARNING",
                "LOW",
                "Access logging is not enabled for bucket demo-data-bucket.",
                "Enable S3 access logging where audit requirements justify it."
        ));

        // Simulated HTTPS enforcement
        findings.add(new SecurityFinding(
                "CS-S3-005",
                "S3 HTTPS Enforcement",
                "PASS",
                "NONE",
                "Bucket policy requires secure transport.",
                "No action required."
        ));

        // Simulated public bucket policy access
findings.add(new SecurityFinding(
        "CS-S3-006",
        "S3 Bucket Policy Public Access",
        "WARNING",
        "HIGH",
        "Bucket policy contains an Allow statement with a public Principal.",
        "Remove unrestricted public principals unless public access is explicitly required. Restrict access to specific AWS accounts, roles, or services."
));

// Simulated cross-account access
findings.add(new SecurityFinding(
        "CS-S3-007",
        "S3 Cross-Account Access",
        "WARNING",
        "MEDIUM",
        "Bucket policy grants access to an explicit AWS account principal.",
        "Verify that cross-account access is intentional and restrict permissions to only the required AWS accounts, roles, or resources."
));

                // Simulated S3 Object Ownership check
        findings.add(new SecurityFinding(
                "CS-S3-008",
                "S3 Object Ownership",
                "WARNING",
                "MEDIUM",
                "S3 Object Ownership is not configured as BucketOwnerEnforced.",
                "Configure S3 Object Ownership as BucketOwnerEnforced to eliminate ACL-based ownership issues where compatible."
        ));

        // Simulated public write/delete access
findings.add(new SecurityFinding(
        "CS-S3-009",
        "S3 Public Write/Delete Access",
        "WARNING",
        "HIGH",
        "Bucket demo-public-bucket allows public write access through its bucket policy.",
        "Remove public write/delete permissions and restrict access to trusted principals and only the actions required."
));

        return findings;
    }
}