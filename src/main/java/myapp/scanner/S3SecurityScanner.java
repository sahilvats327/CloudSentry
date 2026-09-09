
package myapp.scanner;

import myapp.config.AwsClientFactory;
import myapp.model.SecurityFinding;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.GetBucketEncryptionRequest;
import software.amazon.awssdk.services.s3.model.GetBucketLoggingRequest;
import software.amazon.awssdk.services.s3.model.GetBucketPolicyRequest;
import software.amazon.awssdk.services.s3.model.GetBucketPolicyResponse;
import software.amazon.awssdk.services.s3.model.GetBucketVersioningRequest;
import software.amazon.awssdk.services.s3.model.GetPublicAccessBlockRequest;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadBucketResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.services.s3.model.GetBucketOwnershipControlsRequest;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Service
public class S3SecurityScanner {

   private S3Client s3Client;
   private StsClient stsClient;

private final AwsClientFactory awsClientFactory;
private final ObjectMapper objectMapper;

    public S3SecurityScanner(
        S3Client s3Client,
        AwsClientFactory awsClientFactory,
        ObjectMapper objectMapper) {

    this.s3Client = s3Client;
    this.awsClientFactory = awsClientFactory;
    this.objectMapper = objectMapper;
}

    public List<SecurityFinding> scan(String region) {

    if (region == null || region.isBlank()) {
        region = "ap-south-1";
    }

    s3Client =
            awsClientFactory.createS3Client(region);

    stsClient =
            awsClientFactory.createStsClient(region);

    List<SecurityFinding> findings = new ArrayList<>();

        System.out.println();
        System.out.println("[Security] S3 Bucket Checks");
        System.out.println("--------------------------------");

        try {

            var response = s3Client.listBuckets();

            if (response.buckets().isEmpty()) {
                System.out.println("No S3 buckets found.");
                return findings;
            }

            for (Bucket bucket : response.buckets()) {

                String bucketName = bucket.name();

                System.out.println();
                System.out.println("Bucket: " + bucketName);

                String bucketRegion =
                        getBucketRegion(bucketName);

                if (bucketRegion == null) {

                    System.out.println(
                            "Region: Unable to determine"
                    );

                } else {

                    System.out.println(
                            "Region: " + bucketRegion
                    );

                    if (!bucketRegion.equals(
                            s3Client.serviceClientConfiguration()
                                    .region()
                                    .id())) {

                        s3Client =
                                awsClientFactory.createS3Client(
                                        bucketRegion
                                );
                    }
                }

                findings.add(
                        checkPublicAccess(bucketName)
                );

                findings.add(
                        checkEncryption(bucketName)
                );

                findings.add(
                        checkVersioning(bucketName)
                );

                findings.add(
                        checkLogging(bucketName)
                );

                findings.add(
                        checkHttpsOnly(bucketName)
                );
                
                findings.add(
                        checkPublicBucketPolicy(bucketName)
                );
                
                findings.add(
                        checkCrossAccountAccess(bucketName)
);
                findings.add(
                        checkPublicWriteDeleteAccess(bucketName)
);
                findings.add(
                        checkObjectOwnership(bucketName)
);
            }

        } catch (Exception e) {

            System.out.println(
                    "S3 scan failed: " + e.getMessage()
            );
        }

        return findings;
    }

    private String getBucketRegion(String bucketName) {

        try {

            HeadBucketResponse response =
                    s3Client.headBucket(
                            HeadBucketRequest.builder()
                                    .bucket(bucketName)
                                    .build()
                    );

            String region =
                    response.sdkHttpResponse()
                            .firstMatchingHeader(
                                    "x-amz-bucket-region"
                            )
                            .orElse(null);

            if (region == null || region.isBlank()) {
                return "us-east-1";
            }

            return region;

        } catch (
                software.amazon.awssdk.services.s3.model.S3Exception e) {

            String region =
                    e.awsErrorDetails()
                            .sdkHttpResponse()
                            .firstMatchingHeader(
                                    "x-amz-bucket-region"
                            )
                            .orElse(null);

            if (region != null && !region.isBlank()) {
                return region;
            }

            return null;

        } catch (Exception e) {

            return null;
        }
    }

    private SecurityFinding checkPublicAccess(
            String bucketName) {

        try {

            var response =
                    s3Client.getPublicAccessBlock(
                            GetPublicAccessBlockRequest.builder()
                                    .bucket(bucketName)
                                    .build()
                    );

            var config =
                    response.publicAccessBlockConfiguration();

            boolean secure =
                    Boolean.TRUE.equals(
                            config.blockPublicAcls()
                    )
                    && Boolean.TRUE.equals(
                            config.ignorePublicAcls()
                    )
                    && Boolean.TRUE.equals(
                            config.blockPublicPolicy()
                    )
                    && Boolean.TRUE.equals(
                            config.restrictPublicBuckets()
                    );

            if (secure) {

                System.out.println(
                        "Public Access: BLOCKED          [PASS]"
                );

                return new SecurityFinding(
                        "CS-S3-001",
                        "S3 Public Access",
                        "PASS",
                        "NONE",
                        "Public access is blocked",
                        "No action required. Continue enforcing S3 Block Public Access."
                );

            } else {

                System.out.println(
                        "Public Access: NOT FULLY BLOCKED [WARNING]"
                );

                return new SecurityFinding(
                        "CS-S3-001",
                        "S3 Public Access",
                        "WARNING",
                        "HIGH",
                        "Public access is not fully blocked",
                        "Enable all S3 Block Public Access settings unless public access is explicitly required."
                );
            }

        } catch (Exception e) {

            System.out.println(
                    "Public Access: Unable to check - "
                            + e.getMessage()
            );

            return new SecurityFinding(
                "CS-S3-001",
                    "S3 Public Access",
                    "ERROR",
                    "MEDIUM",
                    "Unable to check public access configuration",
                    "Verify that CloudSentry has permission to read the bucket public access configuration."
            );
        }
    }

    private SecurityFinding checkEncryption(
            String bucketName) {

        try {

            var response =
                    s3Client.getBucketEncryption(
                            GetBucketEncryptionRequest.builder()
                                    .bucket(bucketName)
                                    .build()
                    );

            if (response.serverSideEncryptionConfiguration()
                    != null
                    && !response.serverSideEncryptionConfiguration()
                    .rules()
                    .isEmpty()) {

                System.out.println(
                        "Encryption: ENABLED             [PASS]"
                );

                return new SecurityFinding(
                        "CS-S3-002",
                        "S3 Encryption",
                        "PASS",
                        "NONE",
                        "Server-side encryption is enabled",
                        "No action required. Continue using server-side encryption."
                );

            } else {

                System.out.println(
                        "Encryption: NOT ENABLED         [WARNING]"
                );

                return new SecurityFinding(
                        "CS-S3-002",
                        "S3 Encryption",
                        "WARNING",
                        "HIGH",
                        "Server-side encryption is not enabled",
                        "Enable server-side encryption for the bucket to protect stored data."
                );
            }

       } catch (Exception e) {

    System.out.println(
            "Encryption: Unable to check    [ERROR]"
    );

    return new SecurityFinding(
            "CS-S3-002",
            "S3 Encryption",
            "ERROR",
            "MEDIUM",
            "Unable to confirm server-side encryption",
            "Verify that CloudSentry has permission to read the bucket encryption configuration."
    );
}
    }

    private SecurityFinding checkVersioning(
            String bucketName) {

        try {

            var response =
                    s3Client.getBucketVersioning(
                            GetBucketVersioningRequest.builder()
                                    .bucket(bucketName)
                                    .build()
                    );

            if ("Enabled".equalsIgnoreCase(
                    response.statusAsString())) {

                System.out.println(
                        "Versioning: ENABLED             [PASS]"
                );

                return new SecurityFinding(
                        "CS-S3-003",
                        "S3 Versioning",
                        "PASS",
                        "NONE",
                        "Bucket versioning is enabled",
                        "No action required. Continue using versioning to protect against accidental changes."
                );

            } else {

                System.out.println(
                        "Versioning: DISABLED            [WARNING]"
                );

                return new SecurityFinding(
                        "CS-S3-003",
                        "S3 Versioning",
                        "WARNING",
                        "LOW",
                        "Bucket versioning is disabled",
                        "Enable bucket versioning to help recover from accidental deletion or object overwrites."
                );
            }

        } catch (Exception e) {

            System.out.println(
                    "Versioning: Unable to check"
            );

            return new SecurityFinding(
                "CS-S3-003",
                    "S3 Versioning",
                    "ERROR",
                    "LOW",
                    "Unable to check bucket versioning",
                    "Verify that CloudSentry has permission to read the bucket versioning configuration."
            );
        }
    }

    private SecurityFinding checkLogging(
            String bucketName) {

        try {

            var response =
                    s3Client.getBucketLogging(
                            GetBucketLoggingRequest.builder()
                                    .bucket(bucketName)
                                    .build()
                    );

            var loggingEnabled =
                    response.loggingEnabled();

            if (loggingEnabled != null) {

                System.out.println(
                        "Logging: ENABLED               [PASS]"
                );

                return new SecurityFinding(
                        "CS-S3-004",
                        "S3 Logging",
                        "PASS",
                        "NONE",
                        "Bucket logging is enabled",
                        "No action required. Continue monitoring bucket activity."
                );

            } else {

                System.out.println(
                        "Logging: DISABLED              [WARNING]"
                );

                return new SecurityFinding(
                        "CS-S3-004",
                        "S3 Logging",
                        "WARNING",
                        "MEDIUM",
                        "Bucket logging is disabled",
                        "Enable appropriate logging and monitoring to improve security auditing and visibility."
                );
            }

        } catch (Exception e) {

            System.out.println(
                    "Logging: Unable to check"
            );

            return new SecurityFinding(
                "CS-S3-004",
                    "S3 Logging",
                    "ERROR",
                    "MEDIUM",
                    "Unable to check bucket logging configuration",
                    "Verify that CloudSentry has permission to read the bucket logging configuration."
            );
        }
    }

    private SecurityFinding checkHttpsOnly(
        String bucketName) {

    try {

        GetBucketPolicyResponse response =
                s3Client.getBucketPolicy(
                        GetBucketPolicyRequest.builder()
                                .bucket(bucketName)
                                .build()
                );

        String policy = response.policy();

        if (policy == null || policy.isBlank()) {

            System.out.println(
                    "HTTPS Enforcement: NOT CONFIGURED [WARNING]"
            );

            return new SecurityFinding(
                "CS-S3-005",
                    "S3 HTTPS Enforcement",
                    "WARNING",
                    "MEDIUM",
                    "No bucket policy is configured to enforce HTTPS-only access",
                    "Add a bucket policy statement that denies requests when aws:SecureTransport is false."
            );
        }

        String decodedPolicy =
                URLDecoder.decode(
                        policy,
                        StandardCharsets.UTF_8
                );

        JsonNode root =
                objectMapper.readTree(decodedPolicy);

        JsonNode statements =
        getPolicyStatements(root);

if (statements == null) {
            System.out.println(
                    "HTTPS Enforcement: NOT CONFIRMED [WARNING]"
            );

            return new SecurityFinding(
                "CS-S3-005",
                    "S3 HTTPS Enforcement",
                    "WARNING",
                    "MEDIUM",
                    "Bucket policy does not contain a valid statement structure for HTTPS enforcement",
                    "Configure a bucket policy that explicitly denies insecure HTTP requests."
            );
        }

        boolean httpsEnforced = false;

        for (JsonNode statement : statements) {

            /*
             * HTTPS enforcement requires:
             *
             * Effect = Deny
             * Condition -> Bool
             * aws:SecureTransport = false
             */

            String effect =
                    statement.path("Effect").asText("");

            if (!"Deny".equalsIgnoreCase(effect)) {
                continue;
            }

            JsonNode condition =
                    statement.get("Condition");

            if (condition == null || !condition.isObject()) {
                continue;
            }

            JsonNode boolCondition =
                    condition.get("Bool");

            if (boolCondition == null
                    || !boolCondition.isObject()) {
                continue;
            }

            JsonNode secureTransport =
                    boolCondition.get("aws:SecureTransport");

            if (secureTransport == null) {
                continue;
            }

            if (secureTransport.isTextual()
                    && "false".equalsIgnoreCase(
                            secureTransport.asText())) {

                httpsEnforced = true;
                break;
            }

            if (secureTransport.isBoolean()
                    && !secureTransport.asBoolean()) {

                httpsEnforced = true;
                break;
            }
        }

        if (httpsEnforced) {

            System.out.println(
                    "HTTPS Enforcement: ENABLED       [PASS]"
            );

            return new SecurityFinding(
                    "CS-S3-005",
                    "S3 HTTPS Enforcement",
                    "PASS",
                    "NONE",
                    "Bucket policy explicitly denies insecure HTTP requests",
                    "No action required. Continue enforcing HTTPS-only access."
            );
        }

        System.out.println(
                "HTTPS Enforcement: NOT CONFIRMED [WARNING]"
        );

        return new SecurityFinding(
                "CS-S3-005",
                "S3 HTTPS Enforcement",
                "WARNING",
                "MEDIUM",
                "Bucket policy does not explicitly deny insecure HTTP requests",
                "Add a Deny statement using aws:SecureTransport set to false."
        );

    } catch (
            software.amazon.awssdk.services.s3.model.S3Exception e) {

        if (e.statusCode() == 403) {

            System.out.println(
                    "HTTPS Enforcement: ACCESS DENIED [ERROR]"
            );

            return new SecurityFinding(
                    "CS-S3-005",
                    "S3 HTTPS Enforcement",
                    "ERROR",
                    "MEDIUM",
                    "Unable to read the bucket policy because access was denied",
                    "Grant CloudSentry permission to read S3 bucket policies."
            );
        }

        if (e.statusCode() == 404) {

            System.out.println(
                    "HTTPS Enforcement: NO BUCKET POLICY [WARNING]"
            );

            return new SecurityFinding(
                    "CS-S3-005",
                    "S3 HTTPS Enforcement",
                    "WARNING",
                    "MEDIUM",
                    "No bucket policy is configured to enforce HTTPS-only access",
                    "Configure a bucket policy that denies requests when aws:SecureTransport is false."
            );
        }

        System.out.println(
                "HTTPS Enforcement: Unable to check"
        );

        return new SecurityFinding(
                "CS-S3-005",
                "S3 HTTPS Enforcement",
                "ERROR",
                "MEDIUM",
                "Unable to determine whether HTTPS-only access is enforced",
                "Verify that CloudSentry has permission to read the bucket policy."
        );

    } catch (Exception e) {

        System.out.println(
                "HTTPS Enforcement: Unable to check"
        );

        return new SecurityFinding(
                "CS-S3-005",
                "S3 HTTPS Enforcement",
                "ERROR",
                "MEDIUM",
                "Unable to parse or analyze the bucket policy",
                "Verify that the bucket policy is valid JSON and can be read by CloudSentry."
        );
    }
}
    private SecurityFinding checkPublicBucketPolicy(
        String bucketName) {

    try {

        GetBucketPolicyResponse response =
                s3Client.getBucketPolicy(
                        GetBucketPolicyRequest.builder()
                                .bucket(bucketName)
                                .build()
                );

        String policy = response.policy();

        if (policy == null || policy.isBlank()) {

            System.out.println(
                    "Bucket Policy Public Access: NOT DETECTED [PASS]"
            );

            return new SecurityFinding(
                "CS-S3-006",
                    "S3 Bucket Policy Public Access",
                    "PASS",
                    "NONE",
                    "No bucket policy allowing public access was detected",
                    "No action required. Continue reviewing bucket policies regularly."
            );
        }

        // AWS may return the policy URL-encoded.
        String decodedPolicy =
                URLDecoder.decode(
                        policy,
                        StandardCharsets.UTF_8
                );

        JsonNode root =
                objectMapper.readTree(decodedPolicy);

        JsonNode statements =
        getPolicyStatements(root);

if (statements == null) {

            System.out.println(
                    "Bucket Policy Public Access: NOT DETECTED [PASS]"
            );

            return new SecurityFinding(
                "CS-S3-006",
                    "S3 Bucket Policy Public Access",
                    "PASS",
                    "NONE",
                    "No public Allow statement was detected",
                    "No action required. Continue reviewing bucket policies regularly."
            );
        }

        boolean publicAccessDetected = false;

        for (JsonNode statement : statements) {

            String effect =
                    statement.path("Effect").asText("");

            if (!"Allow".equalsIgnoreCase(effect)) {
                continue;
            }

            JsonNode principal =
                    statement.get("Principal");

            if (principal == null) {
                continue;
            }

            // Principal: "*"
            if (principal.isTextual()
                    && "*".equals(principal.asText())) {

                publicAccessDetected = true;
                break;
            }

            // Principal: {"AWS": "*"}
            if (principal.isObject()) {

                JsonNode awsPrincipal =
                        principal.get("AWS");

                if (awsPrincipal != null
                        && awsPrincipal.isTextual()
                        && "*".equals(awsPrincipal.asText())) {

                    publicAccessDetected = true;
                    break;
                }

                // Principal: {"AWS": ["*", ...]}
                if (awsPrincipal != null
                        && awsPrincipal.isArray()) {

                    for (JsonNode principalValue :
                            awsPrincipal) {

                        if ("*".equals(
                                principalValue.asText())) {

                            publicAccessDetected = true;
                            break;
                        }
                    }
                }
            }

            if (publicAccessDetected) {
                break;
            }
        }

        if (publicAccessDetected) {

            System.out.println(
                    "Bucket Policy Public Access: DETECTED [WARNING]"
            );

            return new SecurityFinding(
                    "CS-S3-006",
                    "S3 Bucket Policy Public Access",
                    "WARNING",
                    "HIGH",
                    "Bucket policy contains an Allow statement with a public Principal",
                    "Remove unrestricted public principals unless public access is explicitly required. Restrict access to specific AWS accounts, roles, or services."
            );
        }

        System.out.println(
                "Bucket Policy Public Access: NOT DETECTED [PASS]"
        );

        return new SecurityFinding(
                "CS-S3-006",
                "S3 Bucket Policy Public Access",
                "PASS",
                "NONE",
                "No public Allow statement was detected in the bucket policy",
                "No action required. Continue reviewing bucket policies regularly."
        );

    } catch (
            software.amazon.awssdk.services.s3.model.S3Exception e) {

        if (e.statusCode() == 403) {

            System.out.println(
                    "Bucket Policy Public Access: ACCESS DENIED [ERROR]"
            );

            return new SecurityFinding(
                "CS-S3-006",
                    "S3 Bucket Policy Public Access",
                    "ERROR",
                    "MEDIUM",
                    "Unable to read the bucket policy because access was denied",
                    "Grant CloudSentry permission to read S3 bucket policies."
            );
        }

        if (e.statusCode() == 404) {

            System.out.println(
                    "Bucket Policy Public Access: NO POLICY [PASS]"
            );

            return new SecurityFinding(
                "CS-S3-006",
                    "S3 Bucket Policy Public Access",
                    "PASS",
                    "NONE",
                    "No bucket policy is configured",
                    "No action required. Continue using S3 Block Public Access and other access controls."
            );
        }

        System.out.println(
                "Bucket Policy Public Access: Unable to check"
        );

        return new SecurityFinding(
                "CS-S3-006",
                "S3 Bucket Policy Public Access",
                "ERROR",
                "MEDIUM",
                "Unable to determine whether the bucket policy permits public access",
                "Verify that CloudSentry has permission to read the bucket policy."
        );

    } catch (Exception e) {

        System.out.println(
                "Bucket Policy Public Access: Unable to check"
        );

        return new SecurityFinding(
                "CS-S3-006",
                "S3 Bucket Policy Public Access",
                "ERROR",
                "MEDIUM",
                "Unable to parse or analyze the bucket policy",
                "Verify that the bucket policy is valid JSON and that CloudSentry can read it."
        );
    }
}
private SecurityFinding checkCrossAccountAccess(
        String bucketName) {

    try {

        /*
         * Get the AWS account ID that CloudSentry
         * is currently authenticated against.
         */
        String currentAccountId =
                stsClient.getCallerIdentity(
                        GetCallerIdentityRequest.builder()
                                .build()
                ).account();

        if (currentAccountId == null
                || currentAccountId.isBlank()) {

            return new SecurityFinding(
                    "CS-S3-007",
                    "S3 Cross-Account Access",
                    "ERROR",
                    "MEDIUM",
                    "Unable to determine the current AWS account ID.",
                    "Verify that CloudSentry can call AWS STS GetCallerIdentity."
            );
        }

        GetBucketPolicyResponse response =
                s3Client.getBucketPolicy(
                        GetBucketPolicyRequest.builder()
                                .bucket(bucketName)
                                .build()
                );

        String policy = response.policy();

        if (policy == null || policy.isBlank()) {

            System.out.println(
                    "Cross-Account Access: NOT DETECTED [PASS]"
            );

            return new SecurityFinding(
                    "CS-S3-007",
                    "S3 Cross-Account Access",
                    "PASS",
                    "NONE",
                    "No bucket policy granting cross-account access was detected.",
                    "No action required. Continue reviewing bucket policies regularly."
            );
        }

        String decodedPolicy =
                URLDecoder.decode(
                        policy,
                        StandardCharsets.UTF_8
                );

        JsonNode root =
                objectMapper.readTree(decodedPolicy);

        JsonNode statements =
                getPolicyStatements(root);

        if (statements == null) {

            System.out.println(
                    "Cross-Account Access: NOT DETECTED [PASS]"
            );

            return new SecurityFinding(
                    "CS-S3-007",
                    "S3 Cross-Account Access",
                    "PASS",
                    "NONE",
                    "No analyzable cross-account policy statement was detected.",
                    "No action required. Continue reviewing bucket policies regularly."
            );
        }

        boolean crossAccountDetected = false;
        String crossAccountPrincipal = "";

        for (JsonNode statement : statements) {

            String effect =
                    statement.path("Effect").asText("");

            if (!"Allow".equalsIgnoreCase(effect)) {
                continue;
            }

            JsonNode principal =
                    statement.get("Principal");

            if (principal == null) {
                continue;
            }

            /*
             * Principal can be:
             *
             * "arn:aws:iam::123456789012:root"
             *
             * or:
             *
             * {
             *     "AWS": "arn:aws:iam::123456789012:root"
             * }
             *
             * or:
             *
             * {
             *     "AWS": [
             *         "arn:aws:iam::123456789012:root"
             *     ]
             * }
             */

            List<String> awsPrincipals =
                    new ArrayList<>();

            if (principal.isTextual()) {

                awsPrincipals.add(
                        principal.asText()
                );

            } else if (principal.isObject()) {

                JsonNode awsPrincipal =
                        principal.get("AWS");

                if (awsPrincipal != null) {

                    if (awsPrincipal.isTextual()) {

                        awsPrincipals.add(
                                awsPrincipal.asText()
                        );

                    } else if (awsPrincipal.isArray()) {

                        for (JsonNode principalValue :
                                awsPrincipal) {

                            if (principalValue.isTextual()) {

                                awsPrincipals.add(
                                        principalValue.asText()
                                );
                            }
                        }
                    }
                }
            }

            /*
             * Compare every explicit AWS account principal
             * against the account CloudSentry is running in.
             */
            for (String principalArn :
                    awsPrincipals) {

                if (!principalArn.startsWith(
                        "arn:aws:iam::")) {

                    continue;
                }

                String[] arnParts =
                        principalArn.split(":");

                if (arnParts.length < 5) {
                    continue;
                }

                String principalAccountId =
                        arnParts[4];

                /*
                 * Only report the finding when the
                 * principal belongs to another account.
                 */
                if (!currentAccountId.equals(
                        principalAccountId)) {

                    crossAccountDetected = true;
                    crossAccountPrincipal =
                            principalArn;

                    break;
                }
            }

            if (crossAccountDetected) {
                break;
            }
        }

        if (crossAccountDetected) {

            System.out.println(
                    "Cross-Account Access: DETECTED [WARNING]"
            );

            return new SecurityFinding(
                    "CS-S3-007",
                    "S3 Cross-Account Access",
                    "WARNING",
                    "MEDIUM",
                    "Bucket policy grants access to an AWS principal from another account: "
                            + crossAccountPrincipal,
                    "Verify that the cross-account access is intentional and restrict permissions to only the required AWS account, role, or resource."
            );
        }

        System.out.println(
                "Cross-Account Access: NOT DETECTED [PASS]"
        );

        return new SecurityFinding(
                "CS-S3-007",
                "S3 Cross-Account Access",
                "PASS",
                "NONE",
                "No explicit cross-account AWS principal was detected.",
                "No action required. Continue reviewing bucket policies regularly."
        );

    } catch (
            software.amazon.awssdk.services.s3.model.S3Exception e) {

        if (e.statusCode() == 403) {

            System.out.println(
                    "Cross-Account Access: ACCESS DENIED [ERROR]"
            );

            return new SecurityFinding(
                    "CS-S3-007",
                    "S3 Cross-Account Access",
                    "ERROR",
                    "MEDIUM",
                    "Unable to read the bucket policy because access was denied.",
                    "Grant CloudSentry permission to read S3 bucket policies."
            );
        }

        if (e.statusCode() == 404) {

            System.out.println(
                    "Cross-Account Access: NO POLICY [PASS]"
            );

            return new SecurityFinding(
                    "CS-S3-007",
                    "S3 Cross-Account Access",
                    "PASS",
                    "NONE",
                    "No bucket policy is configured.",
                    "No action required. Continue using least-privilege access controls."
            );
        }

        System.out.println(
                "Cross-Account Access: Unable to check"
        );

        return new SecurityFinding(
                "CS-S3-007",
                "S3 Cross-Account Access",
                "ERROR",
                "MEDIUM",
                "Unable to determine whether cross-account access is configured.",
                "Verify that CloudSentry has permission to read the bucket policy."
        );

    } catch (Exception e) {

        System.out.println(
                "Cross-Account Access: Unable to check"
        );

        return new SecurityFinding(
                "CS-S3-007",
                "S3 Cross-Account Access",
                "ERROR",
                "MEDIUM",
                "Unable to parse or analyze the bucket policy or determine the current AWS account.",
                "Verify that the bucket policy is valid JSON and that CloudSentry can access AWS STS and S3 bucket policies."
        );
    }
}
// =========================================================
// S3 OBJECT OWNERSHIP CHECK
// =========================================================

private SecurityFinding checkObjectOwnership(
        String bucketName) {

    try {

        var response =
                s3Client.getBucketOwnershipControls(
                        GetBucketOwnershipControlsRequest.builder()
                                .bucket(bucketName)
                                .build()
                );

        var ownershipControls =
                response.ownershipControls();

        if (ownershipControls == null
                || ownershipControls.rules() == null
                || ownershipControls.rules().isEmpty()) {

            System.out.println(
                    "Object Ownership: NOT CONFIGURED [WARNING]"
            );

            return new SecurityFinding(
                    "CS-S3-008",
                    "S3 Object Ownership",
                    "WARNING",
                    "MEDIUM",
                    "S3 Object Ownership controls are not explicitly configured.",
                    "Configure S3 Object Ownership and prefer BucketOwnerEnforced to eliminate ACL-based ownership issues."
            );
        }

        var rules =
                ownershipControls.rules();

        String ownership =
                rules.get(0).objectOwnershipAsString();

        if ("BucketOwnerEnforced".equalsIgnoreCase(ownership)) {

            System.out.println(
                    "Object Ownership: BUCKET OWNER ENFORCED [PASS]"
            );

            return new SecurityFinding(
                    "CS-S3-008",
                    "S3 Object Ownership",
                    "PASS",
                    "NONE",
                    "S3 Object Ownership is configured as BucketOwnerEnforced.",
                    "No action required. Continue using BucketOwnerEnforced where appropriate."
            );

        } else {

            System.out.println(
                    "Object Ownership: "
                            + ownership
                            + " [WARNING]"
            );

            return new SecurityFinding(
                    "CS-S3-008",
                    "S3 Object Ownership",
                    "WARNING",
                    "MEDIUM",
                    "S3 Object Ownership is configured as "
                            + ownership
                            + " instead of BucketOwnerEnforced.",
                    "Prefer BucketOwnerEnforced to disable ACL-based ownership management when compatible with the workload."
            );
        }

    } catch (
            software.amazon.awssdk.services.s3.model.S3Exception e) {

        if (e.statusCode() == 404) {

            System.out.println(
                    "Object Ownership: NOT CONFIGURED [WARNING]"
            );

            return new SecurityFinding(
                    "CS-S3-008",
                    "S3 Object Ownership",
                    "WARNING",
                    "MEDIUM",
                    "S3 Object Ownership controls are not configured.",
                    "Configure S3 Object Ownership and prefer BucketOwnerEnforced where appropriate."
            );
        }

        if (e.statusCode() == 403) {

            System.out.println(
                    "Object Ownership: ACCESS DENIED [ERROR]"
            );

            return new SecurityFinding(
                    "CS-S3-008",
                    "S3 Object Ownership",
                    "ERROR",
                    "MEDIUM",
                    "Unable to read S3 Object Ownership controls because access was denied.",
                    "Grant CloudSentry permission to read bucket ownership controls."
            );
        }

        System.out.println(
                "Object Ownership: Unable to check"
        );

        return new SecurityFinding(
                "CS-S3-008",
                "S3 Object Ownership",
                "ERROR",
                "MEDIUM",
                "Unable to determine the S3 Object Ownership configuration.",
                "Verify that CloudSentry has permission to read bucket ownership controls."
        );

    } catch (Exception e) {

        System.out.println(
                "Object Ownership: Unable to check"
        );

        return new SecurityFinding(
                "CS-S3-008",
                "S3 Object Ownership",
                "ERROR",
                "MEDIUM",
                "Unable to inspect the S3 Object Ownership configuration.",
                "Verify that the bucket supports Ownership Controls and that CloudSentry has the required permissions."
        );
    }

}
// =========================================================
// S3 PUBLIC WRITE / DELETE ACCESS CHECK
// =========================================================

private SecurityFinding checkPublicWriteDeleteAccess(
        String bucketName) {

    try {

        GetBucketPolicyResponse response =
                s3Client.getBucketPolicy(
                        GetBucketPolicyRequest.builder()
                                .bucket(bucketName)
                                .build()
                );

        String policy = response.policy();

        if (policy == null || policy.isBlank()) {

            System.out.println(
                    "Public Write/Delete Access: NOT DETECTED [PASS]"
            );

            return new SecurityFinding(
                    "CS-S3-009",
                    "S3 Public Write/Delete Access",
                    "PASS",
                    "NONE",
                    "No bucket policy granting public write or delete access was detected.",
                    "No action required. Continue restricting write and delete permissions."
            );
        }

        String decodedPolicy =
                URLDecoder.decode(
                        policy,
                        StandardCharsets.UTF_8
                );

        JsonNode root =
                objectMapper.readTree(decodedPolicy);

        JsonNode statements =
        getPolicyStatements(root);

if (statements == null) {

            return new SecurityFinding(
                    "CS-S3-009",
                    "S3 Public Write/Delete Access",
                    "PASS",
                    "NONE",
                    "No analyzable public write or delete policy statement was detected.",
                    "No action required."
            );
        }

        boolean publicWriteDeleteDetected = false;
        String dangerousAction = "";

        for (JsonNode statement : statements) {

            String effect =
                    statement.path("Effect").asText("");

            if (!"Allow".equalsIgnoreCase(effect)) {
                continue;
            }

            JsonNode principal =
                    statement.get("Principal");

            if (!isPublicPrincipal(principal)) {
                continue;
            }

            JsonNode action =
                    statement.get("Action");

            if (action == null) {
                continue;
            }

            if (action.isTextual()) {

                String actionValue =
                        action.asText();

                if (isWriteDeleteAction(actionValue)) {

                    publicWriteDeleteDetected = true;
                    dangerousAction = actionValue;
                    break;
                }
            }

            if (action.isArray()) {

                for (JsonNode actionNode : action) {

                    if (!actionNode.isTextual()) {
                        continue;
                    }

                    String actionValue =
                            actionNode.asText();

                    if (isWriteDeleteAction(actionValue)) {

                        publicWriteDeleteDetected = true;
                        dangerousAction = actionValue;
                        break;
                    }
                }
            }

            if (publicWriteDeleteDetected) {
                break;
            }
        }

        if (publicWriteDeleteDetected) {

            System.out.println(
                    "Public Write/Delete Access: DETECTED [HIGH]"
            );

            return new SecurityFinding(
                    "CS-S3-009",
                    "S3 Public Write/Delete Access",
                    "WARNING",
                    "HIGH",
                    "Bucket policy allows public access to the sensitive S3 action: "
                            + dangerousAction,
                    "Remove public write/delete permissions and restrict access to trusted principals and only the actions required."
            );
        }

        System.out.println(
                "Public Write/Delete Access: NOT DETECTED [PASS]"
        );

        return new SecurityFinding(
                "CS-S3-009",
                "S3 Public Write/Delete Access",
                "PASS",
                "NONE",
                "No public write or delete access was detected in the bucket policy.",
                "No action required. Continue restricting write and delete permissions."
        );

    } catch (
            software.amazon.awssdk.services.s3.model.S3Exception e) {

        if (e.statusCode() == 403) {

            return new SecurityFinding(
                    "CS-S3-009",
                    "S3 Public Write/Delete Access",
                    "ERROR",
                    "MEDIUM",
                    "Unable to inspect the bucket policy because access was denied.",
                    "Grant CloudSentry permission to read the bucket policy."
            );
        }

        if (e.statusCode() == 404) {

            return new SecurityFinding(
                    "CS-S3-009",
                    "S3 Public Write/Delete Access",
                    "PASS",
                    "NONE",
                    "No bucket policy is configured.",
                    "No action required."
            );
        }

        return new SecurityFinding(
                "CS-S3-009",
                "S3 Public Write/Delete Access",
                "ERROR",
                "MEDIUM",
                "Unable to determine whether the bucket permits public write or delete access.",
                "Verify that CloudSentry can read the bucket policy."
        );

    } catch (Exception e) {

        return new SecurityFinding(
                "CS-S3-009",
                "S3 Public Write/Delete Access",
                "ERROR",
                "MEDIUM",
                "Unable to parse or analyze the bucket policy.",
                "Verify that the bucket policy is valid JSON and can be read by CloudSentry."
        );
    }
}

private boolean isPublicPrincipal(JsonNode principal) {

    if (principal == null) {
        return false;
    }

    if (principal.isTextual()) {
        return "*".equals(principal.asText());
    }

    if (principal.isObject()) {

        JsonNode awsPrincipal =
                principal.get("AWS");

        if (awsPrincipal == null) {
            return false;
        }

        if (awsPrincipal.isTextual()) {
            return "*".equals(awsPrincipal.asText());
        }

        if (awsPrincipal.isArray()) {

            for (JsonNode value : awsPrincipal) {

                if ("*".equals(value.asText())) {
                    return true;
                }
            }
        }
    }

    return false;
}
private boolean isWriteDeleteAction(String action) {

    String normalized =
            action.toLowerCase();

    return normalized.equals("s3:putobject")
            || normalized.equals("s3:deleteobject")
            || normalized.equals("s3:putobjectacl")
            || normalized.equals("s3:putbucketpolicy")
            || normalized.equals("s3:deletebucketpolicy")
            || normalized.equals("s3:*")
            || normalized.equals("*");
}

private JsonNode getPolicyStatements(JsonNode root) {

    JsonNode statements = root.get("Statement");

    if (statements == null) {
        return null;
    }

    if (statements.isArray()) {
        return statements;
    }

    if (statements.isObject()) {
        return objectMapper.createArrayNode().add(statements);
    }

    return null;
}
}

