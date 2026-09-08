package myapp.scanner;

import software.amazon.awssdk.services.iam.model.GetAccessKeyLastUsedRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import myapp.model.SecurityFinding;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.AccessKeyMetadata;
import software.amazon.awssdk.services.iam.model.AttachedPolicy;
import software.amazon.awssdk.services.iam.model.GetAccountPasswordPolicyResponse;
import software.amazon.awssdk.services.iam.model.GetPolicyRequest;
import software.amazon.awssdk.services.iam.model.GetPolicyVersionRequest;
import software.amazon.awssdk.services.iam.model.ListAccessKeysRequest;
import software.amazon.awssdk.services.iam.model.ListAttachedUserPoliciesRequest;
import software.amazon.awssdk.services.iam.model.ListMfaDevicesRequest;
import software.amazon.awssdk.services.iam.model.ListUsersResponse;
import software.amazon.awssdk.services.iam.model.NoSuchEntityException;
import software.amazon.awssdk.services.iam.model.Policy;
import software.amazon.awssdk.services.iam.model.PolicyVersion;
import software.amazon.awssdk.services.iam.model.User;
import software.amazon.awssdk.services.iam.model.ListAttachedGroupPoliciesRequest;
import software.amazon.awssdk.services.iam.model.ListGroupsForUserRequest;
import myapp.config.AwsClientFactory;
import software.amazon.awssdk.services.iam.model.GetAccountSummaryRequest;
import software.amazon.awssdk.services.iam.model.GetAccountSummaryResponse;
import software.amazon.awssdk.services.iam.model.ListUserPoliciesRequest;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

@Service
public class IamSecurityScanner implements SecurityScanner {

   private IamClient iamClient;
private final ObjectMapper objectMapper;
private final AwsClientFactory awsClientFactory;

   public IamSecurityScanner(
        IamClient iamClient,
        ObjectMapper objectMapper,
        AwsClientFactory awsClientFactory) {

    this.iamClient = iamClient;
    this.objectMapper = objectMapper;
    this.awsClientFactory = awsClientFactory;
}

    public List<SecurityFinding> scan(String region) {
        if (region != null && !region.isBlank()) {
    iamClient = awsClientFactory.createIamClient(region);
}

        List<SecurityFinding> findings = new ArrayList<>();

        System.out.println();
        System.out.println("========================================");
        System.out.println("          IAM Security Checks");
        System.out.println("========================================");
        checkRootAccountSecurity(findings);
        try {

            ListUsersResponse response = iamClient.listUsers();

            if (response.users().isEmpty()) {

                System.out.println("IAM Users: None found");

                findings.add(new SecurityFinding(
                        "IAM Users",
                        "PASS",
                        "NONE",
                        "No IAM users were found in the account",
                        "No action required."
                ));

                return findings;
            }

            System.out.println(
                    "IAM Users: " + response.users().size()
            );

            for (User user : response.users()) {
            String username = user.userName();

            System.out.println();
            System.out.println("User: " + username);

            checkMfa(username, findings);
            checkAccessKeys(username, findings);
            checkInlinePolicies(username, findings);
            checkAttachedPolicies(username, findings);
            checkGroupPolicies(username, findings);
}

            checkPasswordPolicy(findings);

        } catch (Exception e) {

            System.out.println();
            System.out.println(
                    "IAM Users: Unable to check"
            );

            System.out.println(
                    "IAM Users Error Type: "
                            + e.getClass().getName()
            );

            System.out.println(
                    "IAM Users Error: "
                            + e.getMessage()
            );

            findings.add(new SecurityFinding(
                    "IAM Users",
                    "ERROR",
                    "MEDIUM",
                    "Unable to retrieve IAM users",
                    "Verify that CloudSentry has permission to list IAM users."
            ));
        }

        return findings;
    }
// ==================================================
// ROOT ACCOUNT SECURITY CHECK
// ==================================================

private void checkRootAccountSecurity(
        List<SecurityFinding> findings) {

    System.out.println();
    System.out.println("Root Account Security:");

    try {

        GetAccountSummaryResponse response =
                iamClient.getAccountSummary(
                        GetAccountSummaryRequest.builder()
                                .build()
                );

        var summaryMap =
                response.summaryMap();

        /*
         * AWS account summary provides:
         *
         * AccountMFAEnabled
         * AccountAccessKeysPresent
         *
         * These values represent the account/root-level
         * security state rather than an individual IAM user.
         */

        int mfaEnabled =
                summaryMap.getOrDefault(
                        "AccountMFAEnabled",
                        0
                );

        int accessKeysPresent =
                summaryMap.getOrDefault(
                        "AccountAccessKeysPresent",
                        0
                );

        // ------------------------------------------
        // ROOT MFA
        // ------------------------------------------

        if (mfaEnabled == 1) {

            System.out.println(
                    "Root MFA: ENABLED                 [PASS]"
            );

            findings.add(new SecurityFinding(
        "CS-IAM-001",
        "IAM Root Account MFA",
        "PASS",
        "NONE",
        "MFA is enabled for the AWS account root user",
        "No action required. Continue protecting the root user with MFA."
));

        } else {

            System.out.println(
                    "Root MFA: NOT ENABLED             [WARNING]"
            );

            findings.add(new SecurityFinding(
        "CS-IAM-001",
        "IAM Root Account MFA",
        "WARNING",
        "HIGH",
        "MFA is not enabled for the AWS account root user",
        "Enable MFA for the AWS account root user immediately."
));
        }

        // ------------------------------------------
        // ROOT ACCESS KEYS
        // ------------------------------------------

        if (accessKeysPresent == 0) {

            System.out.println(
                    "Root Access Keys: NONE             [PASS]"
            );

           findings.add(new SecurityFinding(
        "CS-IAM-002",
        "IAM Root Access Keys",
                    "PASS",
                    "NONE",
                    "No root account access keys are present",
                    "No action required. Continue avoiding root access keys."
            ));

        } else {

            System.out.println(
                    "Root Access Keys: PRESENT          [HIGH]"
            );

            findings.add(new SecurityFinding(
        "CS-IAM-002",
        "IAM Root Access Keys",
                    "WARNING",
                    "HIGH",
                    "Root account access keys are present",
                    "Remove root account access keys and use IAM roles or users with least-privilege permissions instead."
            ));
        }

    } catch (Exception e) {

        System.out.println(
                "Root Account Security: UNABLE TO CHECK [ERROR]"
        );

        System.out.println(
                "Root Account Error Type: "
                        + e.getClass().getName()
        );

        System.out.println(
                "Root Account Error: "
                        + e.getMessage()
        );

        findings.add(new SecurityFinding(
                "IAM Root Account Security",
                "ERROR",
                "MEDIUM",
                "Unable to retrieve AWS account-level security information",
                "Verify that CloudSentry has permission to retrieve the IAM account summary."
        ));
    }
}
    // ==================================================
    // MFA CHECK
    // ==================================================

    private void checkMfa(
            String username,
            List<SecurityFinding> findings) {

        try {

            var response = iamClient.listMFADevices(
                    ListMfaDevicesRequest.builder()
                            .userName(username)
                            .build()
            );

            if (response.mfaDevices().isEmpty()) {

                System.out.println(
                        "MFA: NOT ENABLED                [WARNING]"
                );

               findings.add(new SecurityFinding(
        "CS-IAM-003",
        "IAM MFA - " + username,
        "WARNING",
        "MEDIUM",
        "MFA is not enabled for this IAM user",
        "Enable MFA for the IAM user to reduce the risk of account compromise."
));

            } else {

                System.out.println(
                        "MFA: ENABLED                    [PASS]"
                );

                findings.add(new SecurityFinding(
        "CS-IAM-003",
        "IAM MFA - " + username,
        "PASS",
        "NONE",
        "MFA is enabled for this IAM user",
        "No action required. Continue enforcing MFA."
));
            }

        } catch (Exception e) {

            System.out.println(
                    "MFA: UNABLE TO CHECK             [ERROR]"
            );

            findings.add(new SecurityFinding(
                "CS-IAM-003",
                    "IAM MFA - " + username,
                    "ERROR",
                    "MEDIUM",
                    "Unable to determine MFA status for this IAM user",
                    "Verify that CloudSentry has permission to list MFA devices."
            ));
        }
    }

// ACCESS KEY CHECK

private void checkAccessKeys(String username, List<SecurityFinding> findings) {
    try {
        var response = iamClient.listAccessKeys(
                ListAccessKeysRequest.builder()
                        .userName(username)
                        .build()
        );

        int activeKeyCount = 0;

for (AccessKeyMetadata key : response.accessKeyMetadata()) {

        // Check whether the access key is inactive
if ("Inactive".equalsIgnoreCase(key.statusAsString())) {

    System.out.println(
            "Access Key Status: INACTIVE       [WARNING]"
    );

    findings.add(new SecurityFinding(
            "CS-IAM-012",
            "IAM Inactive Access Key - " + username,
            "WARNING",
            "MEDIUM",
            "An inactive access key exists for this IAM user.",
            "Remove inactive access keys when they are no longer required."
    ));
}

    if ("Active".equalsIgnoreCase(key.statusAsString())) {
        activeKeyCount++;
    }
}

if (activeKeyCount >= 2) {

    System.out.println(
            "Active Access Keys: "
                    + activeKeyCount
                    + " [WARNING]"
    );

    findings.add(new SecurityFinding(
            "CS-IAM-011",
            "IAM Multiple Active Access Keys - " + username,
            "WARNING",
            "MEDIUM",
            "IAM user has " + activeKeyCount
                    + " active access keys.",
            "Remove unused access keys and keep only the credentials required for the user's workload."
    ));
}

        if (response.accessKeyMetadata().isEmpty()) {
            System.out.println("Access Keys: NONE               [PASS]");
            findings.add(new SecurityFinding(
        "CS-IAM-004",
        "IAM Access Key Age - " + username,
        "PASS",
        "NONE",
        "Access key age is within the recommended 90-day rotation period",
        "Continue rotating access keys regularly."
));
            return;
        }

        for (AccessKeyMetadata key : response.accessKeyMetadata()) {

                

            long ageInDays =
                    ChronoUnit.DAYS.between(key.createDate(), Instant.now());

            // Check key age
            if (ageInDays > 90) {
                System.out.println(
                        "Access Key Age: " + ageInDays + " days        [WARNING]"
                );

               findings.add(new SecurityFinding(
        "CS-IAM-004",
        "IAM Access Key Age - " + username,
        "WARNING",
        "MEDIUM",
        "An access key is older than 90 days",
        "Rotate or replace old access keys regularly and remove unused keys."
));
            } else {
                System.out.println(
                        "Access Key Age: " + ageInDays + " days          [PASS]"
                );

                findings.add(new SecurityFinding(
                        "CS-IAM-004",
                        "IAM Access Key Age - " + username,
                        "PASS",
                        "NONE",
                        "Access key age is within the recommended 90-day rotation period",
                        "Continue rotating access keys regularly."
                ));
            }

            // Check last usage
            try {
                var lastUsedResponse = iamClient.getAccessKeyLastUsed(
                        GetAccessKeyLastUsedRequest.builder()
                                .accessKeyId(key.accessKeyId())
                                .build()
                );

                var lastUsed = lastUsedResponse.accessKeyLastUsed();

                if (lastUsed == null || lastUsed.lastUsedDate() == null) {

                    System.out.println(
                            "Access Key Usage: NEVER USED       [WARNING]"
                    );

                   findings.add(new SecurityFinding(
        "CS-IAM-005",
        "IAM Access Key Usage - " + username,
        "WARNING",
        "MEDIUM",
        "An access key has never been used",
        "Disable or remove unused access keys to reduce the risk of credential compromise."
));

                } else {

                    long unusedDays =
                            ChronoUnit.DAYS.between(
                                    lastUsed.lastUsedDate(),
                                    Instant.now()
                            );

                    if (unusedDays > 90) {

                        System.out.println(
                                "Access Key Usage: " + unusedDays +
                                " days ago       [WARNING]"
                        );

                        findings.add(new SecurityFinding(
        "CS-IAM-005",
        "IAM Access Key Usage - " + username,
        "WARNING",
        "MEDIUM",
        "An access key has not been used for more than 90 days",
        "Disable or remove unused access keys and rotate credentials regularly."
));

                    } else {

                        System.out.println(
                                "Access Key Usage: " + unusedDays +
                                " days ago         [PASS]"
                        );

                       findings.add(new SecurityFinding(
        "CS-IAM-005",
        "IAM Access Key Usage - " + username,
        "PASS",
        "NONE",
        "An access key has been used within the last 90 days",
        "Continue monitoring access key usage and rotate credentials regularly."
));
                    }
                }

            } catch (Exception e) {

                System.out.println(
                        "Access Key Usage: UNABLE TO CHECK [ERROR]"
                );

               findings.add(new SecurityFinding(
        "CS-IAM-005",
        "IAM Access Key Usage - " + username,
        "ERROR",
        "MEDIUM",
        "Unable to determine the last usage time of an access key",
        "Verify that CloudSentry has permission to retrieve access key usage information."
));
            }
        }

    } catch (Exception e) {

        System.out.println(
                "Access Keys: UNABLE TO CHECK      [ERROR]"
        );

        findings.add(new SecurityFinding(
                "IAM Access Keys - " + username,
                "ERROR",
                "MEDIUM",
                "Unable to retrieve access keys for this IAM user",
                "Verify that CloudSentry has permission to list IAM access keys."
        ));
    }
}

// IAM INLINE POLICY CHECK


private void checkInlinePolicies(
        String username,
        List<SecurityFinding> findings) {

    System.out.println("Inline Policies:");

    try {
        var response = iamClient.listUserPolicies(
                ListUserPoliciesRequest.builder()
                        .userName(username)
                        .build()
        );

        if (response.policyNames().isEmpty()) {
            System.out.println("Inline Policies: NONE              [PASS]");

            findings.add(new SecurityFinding(
                    "CS-IAM-006",
                    "IAM Inline Policies - " + username,
                    "PASS",
                    "NONE",
                    "No inline policies are attached directly to this IAM user",
                    "Continue following the principle of least privilege."
            ));

            return;
        }

        for (String policyName : response.policyNames()) {

            System.out.println("Inline Policy: " + policyName);

            var policyResponse = iamClient.getUserPolicy(
                    software.amazon.awssdk.services.iam.model.GetUserPolicyRequest
                            .builder()
                            .userName(username)
                            .policyName(policyName)
                            .build()
            );

            String decodedDocument = URLDecoder.decode(
                    policyResponse.policyDocument(),
                    StandardCharsets.UTF_8
            );

            JsonNode root = objectMapper.readTree(decodedDocument);

            boolean unrestrictedAction =
        containsUnrestrictedAction(root);

boolean unrestrictedResource =
        containsUnrestrictedResource(root);

boolean serviceWildcard =
        containsServiceWildcard(root);

boolean privilegeEscalationAction =
        containsPrivilegeEscalationAction(root);
            if (unrestrictedAction) {

                System.out.println(
                        "Inline Policy Document: Action '*'      [HIGH]"
                );

                findings.add(new SecurityFinding(
                        "CS-IAM-006",
                        "IAM Inline Policy Analysis - " + username,
                        "WARNING",
                        "HIGH",
                        "Inline policy '" + policyName +
                                "' contains Action '*' which grants unrestricted API actions",
                        "Replace wildcard actions with only the specific AWS actions required by the user."
                ));

            } else if (unrestrictedResource && serviceWildcard) {

                System.out.println(
                        "Inline Policy Document: Broad permissions [HIGH]"
                );

                findings.add(new SecurityFinding(
                        "CS-IAM-006",
                        "IAM Inline Policy Analysis - " + username,
                        "WARNING",
                        "HIGH",
                        "Inline policy '" + policyName +
                                "' grants service-wide permissions against all resources",
                        "Restrict both actions and resources to the minimum permissions required."
                ));

                } else if (privilegeEscalationAction) {

    System.out.println(
            "Policy Document: Privilege escalation action [HIGH]"
    );

    findings.add(new SecurityFinding(
            "CS-IAM-013",
            "IAM Privilege Escalation Risk - " + username,
            "WARNING",
            "HIGH",
            "Policy '" + policyName
                    + "' contains an IAM action that can enable privilege escalation.",
            "Restrict privilege-sensitive IAM actions such as iam:PassRole and policy-management actions to only the identities and resources that require them."
    ));

    } else if (privilegeEscalationAction) {

    System.out.println(
            "Policy Document: Privilege escalation action [HIGH]"
    );

    findings.add(new SecurityFinding(
            "CS-IAM-013",
            "IAM Privilege Escalation Risk - " + username,
            "WARNING",
            "HIGH",
            "Policy '" + policyName
                    + "' contains an IAM action that can enable privilege escalation.",
            "Restrict privilege-sensitive IAM actions such as iam:PassRole and policy-management actions to only the identities and resources that require them."
    ));
    
            } else if (serviceWildcard) {

                System.out.println(
                        "Inline Policy Document: Service wildcard [WARNING]"
                );

                findings.add(new SecurityFinding(
                        "CS-IAM-006",
                        "IAM Inline Policy Analysis - " + username,
                        "WARNING",
                        "MEDIUM",
                        "Inline policy '" + policyName +
                                "' contains service-wide wildcard permissions",
                        "Replace service-wide actions such as service:* with only the required API actions."
                ));

            } else {

                System.out.println(
                        "Inline Policy Document: No broad wildcard detected [PASS]"
                );

                findings.add(new SecurityFinding(
                        "CS-IAM-006",
                        "IAM Inline Policy Analysis - " + username,
                        "PASS",
                        "NONE",
                        "Inline policy '" + policyName +
                                "' does not contain broad wildcard permissions",
                        "Continue following the principle of least privilege."
                ));
            }
        }

    } catch (Exception e) {

        System.out.println(
                "Inline Policies: UNABLE TO CHECK      [ERROR]"
        );

        System.out.println(
                "Inline Policy Error Type: " + e.getClass().getName()
        );

        System.out.println(
                "Inline Policy Error: " + e.getMessage()
        );

        findings.add(new SecurityFinding(
                "CS-IAM-006",
                "IAM Inline Policies - " + username,
                "ERROR",
                "MEDIUM",
                "Unable to retrieve or analyze inline policies for this IAM user",
                "Verify that CloudSentry has permission to list and retrieve IAM user inline policies."
        ));
    }
}


    // ==================================================
    // IAM POLICY CHECK
    // ==================================================

    private void checkAttachedPolicies(
            String username,
            List<SecurityFinding> findings) {

        System.out.println("Policies:");

        try {

            var response = iamClient.listAttachedUserPolicies(
                    ListAttachedUserPoliciesRequest.builder()
                            .userName(username)
                            .build()
            );

            if (response.attachedPolicies().isEmpty()) {

                System.out.println(
                        "Attached Policies: NONE           [PASS]"
                );

                findings.add(new SecurityFinding(
                        "CS-IAM-007",
                        "IAM Policies - " + username,
                        "PASS",
                        "NONE",
                        "No managed policies are directly attached to this IAM user",
                        "Continue following the principle of least privilege."
                ));

                return;
            }

            for (AttachedPolicy attachedPolicy :
                    response.attachedPolicies()) {

                String policyName =
                        attachedPolicy.policyName();
                        if ("AdministratorAccess".equalsIgnoreCase(policyName)) {

    System.out.println(
            "Policy: " + policyName + " [HIGH]"
    );

    findings.add(new SecurityFinding(
            "CS-IAM-010",
            "IAM AdministratorAccess - " + username,
            "WARNING",
            "HIGH",
            "IAM user has the AWS-managed AdministratorAccess policy attached.",
            "Remove AdministratorAccess and replace it with a least-privilege policy containing only the permissions required."
    ));
}

                System.out.println(
                        "Policy: " + policyName
                );

               

                analyzePolicyDocument(
                        username,
                        attachedPolicy,
                        findings,
                        "CS-IAM-007"
                );
            }

        } catch (Exception e) {

            System.out.println(
                    "Attached Policies: UNABLE TO CHECK [ERROR]"
            );

            findings.add(new SecurityFinding(
                    "IAM Policies - " + username,
                    "ERROR",
                    "MEDIUM",
                    "Unable to retrieve managed policies attached to this IAM user",
                    "Verify that CloudSentry has permission to list attached user policies."
            ));
        }
    }
// ==================================================
// IAM GROUP POLICY CHECK
// ==================================================

private void checkGroupPolicies(
        String username,
        List<SecurityFinding> findings) {

    System.out.println("Group Policies:");

    try {

        var groupResponse = iamClient.listGroupsForUser(
                ListGroupsForUserRequest.builder()
                        .userName(username)
                        .build()
        );

        if (groupResponse.groups().isEmpty()) {

            System.out.println(
                    "Groups: NONE                   [PASS]"
            );

            findings.add(new SecurityFinding(
        "CS-IAM-008",
        "IAM Group Policies - " + username,
        "PASS",
        "NONE",
        "IAM user is not a member of any group",
        "No group-based permissions were found for this user."
));

            return;
        }

        for (var group : groupResponse.groups()) {

            String groupName = group.groupName();

            System.out.println(
                    "Group: " + groupName
            );

            var policyResponse =
                    iamClient.listAttachedGroupPolicies(
                            ListAttachedGroupPoliciesRequest.builder()
                                    .groupName(groupName)
                                    .build()
                    );

            if (policyResponse.attachedPolicies().isEmpty()) {

                System.out.println(
                        "Attached Group Policies: NONE"
                );

                continue;
            }

            for (AttachedPolicy attachedPolicy :
                    policyResponse.attachedPolicies()) {

                String policyName =
                        attachedPolicy.policyName();

                System.out.println(
                        "Group Policy: " + policyName
                );

                analyzePolicyDocument(
        username + " / Group: " + groupName,
        attachedPolicy,
        findings,
        "CS-IAM-008"
);
            }
        }

    } catch (Exception e) {

        System.out.println(
                "Group Policies: UNABLE TO CHECK [ERROR]"
        );

        System.out.println(
                "Group Policy Error Type: "
                        + e.getClass().getName()
        );

        System.out.println(
                "Group Policy Error: "
                        + e.getMessage()
        );

        findings.add(new SecurityFinding(
                "IAM Group Policies - " + username,
                "ERROR",
                "MEDIUM",
                "Unable to retrieve IAM group memberships or attached group policies for this user",
                "Verify that CloudSentry has permission to list IAM groups and group policies."
        ));
    }
}
    // ==================================================
    // POLICY DOCUMENT ANALYSIS
    // ==================================================

    private void analyzePolicyDocument(
        String username,
        AttachedPolicy attachedPolicy,
        List<SecurityFinding> findings,
        String ruleId) {

        String policyName =
                attachedPolicy.policyName();

        try {

            /*
             * Get the IAM policy metadata.
             */

            Policy policy = iamClient.getPolicy(
                    GetPolicyRequest.builder()
                            .policyArn(attachedPolicy.policyArn())
                            .build()
            ).policy();

            /*
             * Get the default policy version.
             */

            PolicyVersion policyVersion =
                    iamClient.getPolicyVersion(
                            GetPolicyVersionRequest.builder()
                                    .policyArn(policy.arn())
                                    .versionId(policy.defaultVersionId())
                                    .build()
                    ).policyVersion();

            /*
             * AWS returns the policy document
             * URL encoded.
             */

            String decodedDocument =
                    URLDecoder.decode(
                            policyVersion.document(),
                            StandardCharsets.UTF_8
                    );

            JsonNode root =
                    objectMapper.readTree(decodedDocument);

            boolean unrestrictedAction =
                    containsUnrestrictedAction(root);

            boolean unrestrictedResource =
                    containsUnrestrictedResource(root);

            boolean serviceWildcard =
                    containsServiceWildcard(root);

            /*
             * -----------------------------------------
             * HIGH RISK
             * -----------------------------------------
             */

            if (unrestrictedAction) {

                System.out.println(
                        "Policy Document: Action '*'      [HIGH]"
                );

                findings.add(new SecurityFinding(
                        ruleId,
                        "IAM Policy Analysis - " + username,
                        "WARNING",
                        "HIGH",
                        "Policy '" + policyName
                                + "' contains Action '*' which grants unrestricted API actions",
                        "Replace wildcard actions with only the specific AWS actions required by the user."
                ));

            } else if (unrestrictedResource && serviceWildcard) {

                System.out.println(
                        "Policy Document: Broad permissions [HIGH]"
                );

                findings.add(new SecurityFinding(
                        ruleId,
                        "IAM Policy Analysis - " + username,
                        "WARNING",
                        "HIGH",
                        "Policy '" + policyName
                                + "' grants service-wide permissions against all resources",
                        "Restrict both actions and resources to the minimum permissions required."
                ));

            } else if (serviceWildcard) {

                System.out.println(
                        "Policy Document: Service wildcard [WARNING]"
                );

                findings.add(new SecurityFinding(
                        ruleId,
                        "IAM Policy Analysis - " + username,
                        "WARNING",
                        "MEDIUM",
                        "Policy '" + policyName
                                + "' contains service-wide wildcard permissions",
                        "Replace service-wide actions such as service:* with only the required API actions."
                ));

            } else {

                /*
                 * Do not create another PASS finding here.
                 *
                 * This avoids producing duplicate PASS
                 * findings for the same policy.
                 */

                System.out.println(
                        "Policy Document: No broad wildcard detected [PASS]"
                );
            }

        } catch (Exception e) {

            System.out.println(
                    "Policy Document: UNABLE TO ANALYZE [ERROR]"
            );

            System.out.println(
                    "Policy Analysis Error Type: "
                            + e.getClass().getName()
            );

            System.out.println(
                    "Policy Analysis Error: "
                            + e.getMessage()
            );

            findings.add(new SecurityFinding(
                    ruleId,
                    "IAM Policy Analysis - " + username,
                    "ERROR",
                    "MEDIUM",
                    "Unable to analyze the policy document for '"
                            + policyName + "'",
                    "Verify that CloudSentry has permission to retrieve and inspect IAM policy versions."
            ));
        }
    }

    // ==================================================
    // DETECT ACTION: "*"
    // ==================================================

    private boolean containsUnrestrictedAction(
            JsonNode node) {

        if (node.isObject()) {

            JsonNode action = node.get("Action");

            if (action != null) {

                if (action.isTextual()
                        && "*".equals(action.asText())) {

                    return true;
                }

                if (action.isArray()) {

                    for (JsonNode actionNode : action) {

                        if (actionNode.isTextual()
                                && "*".equals(actionNode.asText())) {

                            return true;
                        }
                    }
                }
            }

            for (JsonNode child : node) {

                if (containsUnrestrictedAction(child)) {
                    return true;
                }
            }
        }

        if (node.isArray()) {

            for (JsonNode child : node) {

                if (containsUnrestrictedAction(child)) {
                    return true;
                }
            }
        }

        return false;
    }

    // ==================================================
    // DETECT RESOURCE: "*"
    // ==================================================

    private boolean containsUnrestrictedResource(
            JsonNode node) {

        if (node.isObject()) {

            JsonNode resource = node.get("Resource");

            if (resource != null) {

                if (resource.isTextual()
                        && "*".equals(resource.asText())) {

                    return true;
                }

                if (resource.isArray()) {

                    for (JsonNode resourceNode : resource) {

                        if (resourceNode.isTextual()
                                && "*".equals(resourceNode.asText())) {

                            return true;
                        }
                    }
                }
            }

            for (JsonNode child : node) {

                if (containsUnrestrictedResource(child)) {
                    return true;
                }
            }
        }

        if (node.isArray()) {

            for (JsonNode child : node) {

                if (containsUnrestrictedResource(child)) {
                    return true;
                }
            }
        }

        return false;
    }

    // ==================================================
    // DETECT SERVICE WILDCARDS
    // Example: s3:*
    // ==================================================

    private boolean containsServiceWildcard(
            JsonNode node) {

        if (node.isObject()) {

            JsonNode action = node.get("Action");

            if (action != null) {

                if (action.isTextual()
                        && isServiceWildcard(action.asText())) {

                    return true;
                }

                if (action.isArray()) {

                    for (JsonNode actionNode : action) {

                        if (actionNode.isTextual()
                                && isServiceWildcard(
                                actionNode.asText())) {

                            return true;
                        }
                    }
                }
            }

            for (JsonNode child : node) {

                if (containsServiceWildcard(child)) {
                    return true;
                }
            }
        }

        if (node.isArray()) {

            for (JsonNode child : node) {

                if (containsServiceWildcard(child)) {
                    return true;
                }
            }
        }

        return false;
    }

    // ==================================================
// DETECT PRIVILEGE ESCALATION ACTIONS
// ==================================================

private boolean containsPrivilegeEscalationAction(
        JsonNode node) {

    if (node.isObject()) {

        JsonNode action = node.get("Action");

        if (action != null) {

            if (action.isTextual()
                    && isPrivilegeEscalationAction(action.asText())) {

                return true;
            }

            if (action.isArray()) {

                for (JsonNode actionNode : action) {

                    if (actionNode.isTextual()
                            && isPrivilegeEscalationAction(
                            actionNode.asText())) {

                        return true;
                    }
                }
            }
        }

        for (JsonNode child : node) {

            if (containsPrivilegeEscalationAction(child)) {
                return true;
            }
        }
    }

    if (node.isArray()) {

        for (JsonNode child : node) {

            if (containsPrivilegeEscalationAction(child)) {
                return true;
            }
        }
    }

    return false;
}

private boolean isPrivilegeEscalationAction(
        String action) {

    return switch (action.toLowerCase()) {

        case "iam:passrole",
             "iam:attachuserpolicy",
             "iam:attachrolepolicy",
             "iam:putuserpolicy",
             "iam:putrolepolicy",
             "iam:createpolicyversion",
             "iam:setdefaultpolicyversion"
                -> true;

        default
                -> false;
    };
}


    private boolean isServiceWildcard(
            String action) {

        /*
         * Matches:
         *
         * s3:*
         * ec2:*
         * iam:*
         *
         * but NOT:
         *
         * *
         * s3:GetObject
         */

        return action.matches(
                "^[a-zA-Z0-9-]+:\\*$"
        );
    }

    // ==================================================
    // PASSWORD POLICY CHECK
    // ==================================================

    private void checkPasswordPolicy(
            List<SecurityFinding> findings) {

        System.out.println();
        System.out.println("Password Policy:");

        try {

            GetAccountPasswordPolicyResponse response =
                    iamClient.getAccountPasswordPolicy();

            var policy = response.passwordPolicy();

            int minimumLength =
                    policy.minimumPasswordLength();

            boolean uppercase =
                    policy.requireUppercaseCharacters();

            boolean lowercase =
                    policy.requireLowercaseCharacters();

            boolean numbers =
                    policy.requireNumbers();

            boolean symbols =
                    policy.requireSymbols();

            boolean strongPasswordPolicy =
                    minimumLength >= 12
                            && uppercase
                            && lowercase
                            && numbers
                            && symbols;

            if (strongPasswordPolicy) {

                System.out.println(
                        "Password Policy: STRONG             [PASS]"
                );

                findings.add(new SecurityFinding(
        "CS-IAM-009",
        "IAM Password Policy",
        "PASS",
        "NONE",
        "Account password policy meets the recommended baseline",
        "No action required. Continue enforcing a strong password policy."
));

            } else {

                System.out.println(
                        "Password Policy: WEAK               [WARNING]"
                );

                findings.add(new SecurityFinding(
                        "CS-IAM-009",
                        "IAM Password Policy",
                        "WARNING",
                        "MEDIUM",
                        "Account password policy does not meet the recommended baseline",
                        "Use a minimum password length of 12 characters and require uppercase, lowercase, numbers, and symbols."
                ));
            }

            System.out.println(
                    "Minimum Length: " + minimumLength
            );

            System.out.println(
                    "Uppercase: " + uppercase
            );

            System.out.println(
                    "Lowercase: " + lowercase
            );

            System.out.println(
                    "Numbers: " + numbers
            );

            System.out.println(
                    "Symbols: " + symbols
            );

        } catch (NoSuchEntityException e) {

            System.out.println(
                    "Password Policy: NOT CONFIGURED     [WARNING]"
            );
findings.add(new SecurityFinding(
        "CS-IAM-009",
        "IAM Password Policy",
        "WARNING",
        "MEDIUM",
        "No account password policy is configured",
        "Configure and enforce a strong IAM password policy if IAM console passwords are used."
));

        } catch (Exception e) {

            System.out.println(
                    "Password Policy: UNABLE TO CHECK     [ERROR]"
            );

            System.out.println(
                    "Password Policy Error Type: "
                            + e.getClass().getName()
            );

            System.out.println(
                    "Password Policy Error: "
                            + e.getMessage()
            );

            findings.add(new SecurityFinding(
        "CS-IAM-009",
        "IAM Password Policy",
        "ERROR",
        "MEDIUM",
        "Unable to retrieve the account password policy",
        "Verify that CloudSentry has permission to retrieve the IAM account password policy."
));
        }
    }
}