package myapp.scanner;

import myapp.config.AwsClientFactory;
import myapp.model.SecurityFinding;
import org.springframework.stereotype.Component;

import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeSecurityGroupsRequest;
import software.amazon.awssdk.services.ec2.model.DescribeSecurityGroupsResponse;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesResponse;
import software.amazon.awssdk.services.ec2.model.Instance;
import software.amazon.awssdk.services.ec2.model.InstanceBlockDeviceMapping;
import software.amazon.awssdk.services.ec2.model.EbsInstanceBlockDevice;
import software.amazon.awssdk.services.ec2.model.IpPermission;
import software.amazon.awssdk.services.ec2.model.IpRange;
import software.amazon.awssdk.services.ec2.model.DescribeVolumesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeVolumesResponse;
import software.amazon.awssdk.services.ec2.model.DescribeSnapshotsRequest;
import software.amazon.awssdk.services.ec2.model.DescribeSnapshotsResponse;
import software.amazon.awssdk.services.ec2.model.Snapshot;
import software.amazon.awssdk.services.ec2.model.DescribeImagesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeImagesResponse;
import software.amazon.awssdk.services.ec2.model.Image;
import software.amazon.awssdk.services.ec2.model.Volume;

import java.util.ArrayList;
import java.util.List;

@Component
public class Ec2SecurityScanner {

    private Ec2Client ec2Client;
    private final AwsClientFactory awsClientFactory;

    public Ec2SecurityScanner(
        Ec2Client ec2Client,
        AwsClientFactory awsClientFactory) {

    this.ec2Client = ec2Client;
    this.awsClientFactory = awsClientFactory;
}

    public List<SecurityFinding> scan(String region) {

    if (region != null && !region.isBlank()) {
        ec2Client = awsClientFactory.createEc2Client(region);
    }

    List<SecurityFinding> findings = new ArrayList<>();

        System.out.println();
        System.out.println("========================================");
        System.out.println("          EC2 SECURITY SCAN");
        System.out.println("========================================");


findings.addAll(scanSecurityGroups());
findings.addAll(scanSensitivePortExposure());
findings.addAll(scanUnrestrictedOutboundTraffic());
findings.addAll(scanIpv6Exposure());
findings.addAll(scanEbsEncryption());
findings.addAll(scanPublicIpExposure());
findings.addAll(scanImdsSecurity());
findings.addAll(scanTerminationProtection());
findings.addAll(scanPublicSnapshots());
findings.addAll(scanUnencryptedSnapshots());
findings.addAll(scanPublicAmis());
findings.addAll(scanUnencryptedVolumes());
      
return findings;
    }

    // =========================================================
    // SECURITY GROUP SCANNER
    // =========================================================

    private List<SecurityFinding> scanSecurityGroups() {

        List<SecurityFinding> findings = new ArrayList<>();

        System.out.println();
        System.out.println("----------------------------------------");
        System.out.println("       Security Group Checks");
        System.out.println("----------------------------------------");

        try {

            DescribeSecurityGroupsResponse response =
                    ec2Client.describeSecurityGroups(
                            DescribeSecurityGroupsRequest.builder().build()
                    );

            System.out.println(
                    "Security Groups: " + response.securityGroups().size()
            );

            for (var securityGroup : response.securityGroups()) {

                System.out.println();
                System.out.println(
                        "Security Group: " + securityGroup.groupName()
                );

                System.out.println(
                        "Group ID: " + securityGroup.groupId()
                );

                for (IpPermission permission :
                        securityGroup.ipPermissions()) {

                    if (permission.ipRanges() == null ||
                            permission.ipRanges().isEmpty()) {
                        continue;
                    }

                    if (permission.fromPort() == null ||
                            permission.toPort() == null) {
                        continue;
                    }

                    int fromPort = permission.fromPort();
                    int toPort = permission.toPort();

                    for (IpRange ipRange : permission.ipRanges()) {

                        String cidr = ipRange.cidrIp();

                        if (!"0.0.0.0/0".equals(cidr)) {
                            continue;
                        }

                        for (int port = fromPort;
                             port <= toPort;
                             port++) {

                            String service = getServiceName(port);
                            String severity = getSeverity(port);

                            System.out.println(
                                    service + " (" + port + "): "
                                            + cidr
                                            + " [" + severity + "]"
                            );

                            findings.add(
                                    new SecurityFinding(
                                        "CS-EC2-001",
                                            "EC2 Security Group - "
                                                    + securityGroup.groupName()
                                                    + " - "
                                                    + service
                                                    + " (" + port + ")",

                                            "WARNING",

                                            severity,

                                            service
                                                    + " port "
                                                    + port
                                                    + " is publicly accessible from "
                                                    + cidr
                                                    + ".",

                                            getRecommendation(port)
                                    )
                            );
                        }
                    }
                }
            }

        } catch (Exception e) {

            System.out.println(
                    "Security group scan failed: "
                            + e.getMessage()
            );

            findings.add(
                    new SecurityFinding(
                        "CS-EC2-001",
                            "EC2 Security Group Scan",
                            "ERROR",
                            "HIGH",
                            "CloudSentry could not inspect EC2 security groups.",
                            "Verify AWS permissions and EC2 service availability."
                    )
            );
        }

        return findings;
    }

    // =========================================================
    // EBS ENCRYPTION SCANNER
    // =========================================================

    private List<SecurityFinding> scanEbsEncryption() {

        List<SecurityFinding> findings = new ArrayList<>();

        System.out.println();
        System.out.println("----------------------------------------");
        System.out.println("          EBS Encryption Checks");
        System.out.println("----------------------------------------");

        try {

            DescribeInstancesResponse response =
                    ec2Client.describeInstances(
                            DescribeInstancesRequest.builder().build()
                    );

            int volumeCount = 0;

            for (var reservation : response.reservations()) {

                for (Instance instance : reservation.instances()) {

                    String instanceId = instance.instanceId();

                    for (InstanceBlockDeviceMapping mapping :
                            instance.blockDeviceMappings()) {

                        EbsInstanceBlockDevice ebs = mapping.ebs();

                        if (ebs == null ||
                                ebs.volumeId() == null) {
                            continue;
                        }

                        volumeCount++;

                        String volumeId = ebs.volumeId();

                        DescribeVolumesResponse volumeResponse =
                                ec2Client.describeVolumes(
                                        DescribeVolumesRequest.builder()
                                                .volumeIds(volumeId)
                                                .build()
                                );

                        if (volumeResponse.volumes().isEmpty()) {
                            continue;
                        }

                        boolean encrypted =
                                volumeResponse.volumes()
                                        .get(0)
                                        .encrypted();

                        if (encrypted) {

                            System.out.println(
                                    "Instance: " + instanceId
                                            + " | Volume: " + volumeId
                                            + " | Encryption: ENABLED [PASS]"
                            );

                            findings.add(
                                    new SecurityFinding(
                                        "CS-EC2-002",
                                            "EC2 EBS Encryption - "
                                                    + volumeId,
                                            "PASS",
                                            "NONE",
                                            "EBS volume is encrypted.",
                                            "No action required. Continue using encryption for EBS volumes."
                                    )
                            );

                        } else {

                            System.out.println(
                                    "Instance: " + instanceId
                                            + " | Volume: " + volumeId
                                            + " | Encryption: DISABLED [HIGH]"
                            );

                            findings.add(
                                    new SecurityFinding(
                                        "CS-EC2-002",
                                            "EC2 EBS Encryption - "
                                                    + volumeId,
                                            "WARNING",
                                            "HIGH",
                                            "EBS volume is not encrypted.",
                                            "Enable EBS encryption to protect data at rest."
                                    )
                            );
                        }
                    }
                }
            }

            System.out.println(
                    "EBS Volumes Found: " + volumeCount
            );

        } catch (Exception e) {

            System.out.println(
                    "EBS encryption scan failed: "
                            + e.getMessage()
            );

            findings.add(
                    new SecurityFinding(
                        "CS-EC2-002",
                            "EC2 EBS Encryption Scan",
                            "ERROR",
                            "HIGH",
                            "CloudSentry could not inspect EC2 EBS volumes.",
                            "Verify AWS permissions and EC2 service availability."
                    )
            );
        }

        return findings;
    }
// =========================================================
// EC2 PUBLIC IP EXPOSURE SCANNER
// =========================================================

private List<SecurityFinding> scanPublicIpExposure() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("----------------------------------------");
    System.out.println("       EC2 Public IP Exposure Checks");
    System.out.println("----------------------------------------");

    try {

        DescribeInstancesResponse response =
                ec2Client.describeInstances(
                        DescribeInstancesRequest.builder().build()
                );

        int instanceCount = 0;
        int publicIpCount = 0;

        for (var reservation : response.reservations()) {

            for (Instance instance : reservation.instances()) {

                instanceCount++;

                String instanceId = instance.instanceId();
                String publicIp = instance.publicIpAddress();

                if (publicIp != null && !publicIp.isBlank()) {

                    publicIpCount++;

                    System.out.println(
                            "Instance: " + instanceId
                                    + " | Public IP: " + publicIp
                                    + " [EXPOSED]"
                    );

                    findings.add(
                            new SecurityFinding(
                                "CS-EC2-003",
                                    "EC2 Public IP Exposure - "
                                            + instanceId,

                                    "WARNING",

                                    "MEDIUM",

                                    "EC2 instance has a public IPv4 address: "
                                            + publicIp,

                                    "Remove unnecessary public IP exposure and use private networking where possible."
                            )
                    );

                } else {

                    System.out.println(
                            "Instance: " + instanceId
                                    + " | Public IP: NONE [PASS]"
                    );

                    findings.add(
                            new SecurityFinding(
                                "CS-EC2-003",
                                    "EC2 Public IP Exposure - "
                                            + instanceId,

                                    "PASS",

                                    "NONE",

                                    "EC2 instance does not have a public IPv4 address.",

                                    "No action required. Continue using private networking where appropriate."
                            )
                    );
                }
            }
        }

        System.out.println(
                "EC2 Instances Found: " + instanceCount
        );

        System.out.println(
                "Instances With Public IPs: " + publicIpCount
        );

    } catch (Exception e) {

        System.out.println(
                "Public IP exposure scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-EC2-003",
                        "EC2 Public IP Exposure Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not inspect EC2 public IP addresses.",
                        "Verify AWS permissions and EC2 service availability."
                )
        );
    }

    return findings;
}
// =========================================================
// EC2 INSTANCE METADATA (IMDS) SECURITY SCANNER
// =========================================================

private List<SecurityFinding> scanImdsSecurity() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("----------------------------------------");
    System.out.println("       EC2 IMDS Security Checks");
    System.out.println("----------------------------------------");

    try {

        DescribeInstancesResponse response =
                ec2Client.describeInstances(
                        DescribeInstancesRequest.builder().build()
                );

        int instanceCount = 0;

        for (var reservation : response.reservations()) {

            for (Instance instance : reservation.instances()) {

                instanceCount++;

                String instanceId = instance.instanceId();

                if (instance.metadataOptions() == null) {

                    System.out.println(
                            "Instance: " + instanceId
                                    + " | IMDS: UNKNOWN"
                    );

                    findings.add(
                            new SecurityFinding(
                                "CS-EC2-004",
                                    "EC2 IMDS Security - " + instanceId,
                                    "ERROR",
                                    "HIGH",
                                    "CloudSentry could not determine the instance metadata configuration.",
                                    "Verify EC2 permissions and inspect the instance metadata options."
                            )
                    );

                    continue;
                }

                String httpTokens =
                        instance.metadataOptions().httpTokensAsString();

                if ("required".equalsIgnoreCase(httpTokens)) {

                    System.out.println(
                            "Instance: " + instanceId
                                    + " | IMDSv2: REQUIRED [PASS]"
                    );

                    findings.add(
                            new SecurityFinding(
                                "CS-EC2-004",
                                    "EC2 IMDS Security - " + instanceId,
                                    "PASS",
                                    "NONE",
                                    "IMDSv2 is required for the EC2 instance.",
                                    "No action required. Continue requiring IMDSv2."
                            )
                    );

                } else {

                    System.out.println(
                            "Instance: " + instanceId
                                    + " | IMDSv2: NOT REQUIRED [WARNING]"
                    );

                    findings.add(
                            new SecurityFinding(
                                "CS-EC2-004",
                                    "EC2 IMDS Security - " + instanceId,
                                    "WARNING",
                                    "MEDIUM",
                                    "IMDSv2 is not required for the EC2 instance.",
                                    "Configure the instance metadata service to require IMDSv2."
                            )
                    );
                }
            }
        }

        System.out.println(
                "EC2 Instances Checked: " + instanceCount
        );

    } catch (Exception e) {

        System.out.println(
                "IMDS security scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-EC2-004",
                        "EC2 IMDS Security Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not inspect EC2 instance metadata settings.",
                        "Verify AWS permissions and EC2 service availability."
                )
        );
    }

    return findings;
}
    // =========================================================
    // SERVICE NAME
    // =========================================================
// =========================================================
// EC2 TERMINATION PROTECTION CHECK
// =========================================================

private List<SecurityFinding> scanTerminationProtection() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("----------------------------------------");
    System.out.println("       EC2 Termination Protection Checks");
    System.out.println("----------------------------------------");

    try {

        DescribeInstancesResponse response =
                ec2Client.describeInstances(
                        DescribeInstancesRequest.builder().build()
                );

        int instanceCount = 0;

        for (var reservation : response.reservations()) {

            for (Instance instance : reservation.instances()) {

                instanceCount++;

                String instanceId = instance.instanceId();

               boolean terminationProtection =
        ec2Client.describeInstanceAttribute(
                software.amazon.awssdk.services.ec2.model.DescribeInstanceAttributeRequest
                        .builder()
                        .instanceId(instanceId)
                        .attribute("disableApiTermination")
                        .build()
        ).disableApiTermination().value();

                if (terminationProtection) {

                    System.out.println(
                            "Instance: " + instanceId
                                    + " | Termination Protection: ENABLED [PASS]"
                    );

                    findings.add(
                            new SecurityFinding(
                                "CS-EC2-005",
                                    "EC2 Termination Protection - "
                                            + instanceId,
                                    "PASS",
                                    "NONE",
                                    "API termination protection is enabled for the EC2 instance.",
                                    "No action required. Continue protecting important instances from accidental termination."
                            )
                    );

                } else {

                    System.out.println(
                            "Instance: " + instanceId
                                    + " | Termination Protection: DISABLED [INFO]"
                    );

                    findings.add(
                            new SecurityFinding(
                                    "CS-EC2-005",
                                    "EC2 Termination Protection - "
                                            + instanceId,
                                    "INFO",
                                    "LOW",
                                    "API termination protection is not enabled for the EC2 instance.",
                                    "Consider enabling termination protection for important production instances."
                            )
                    );
                }
            }
        }

        System.out.println(
                "EC2 Instances Checked: " + instanceCount
        );

    } catch (Exception e) {

        System.out.println(
                "Termination protection scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-EC2-005",
                        "EC2 Termination Protection Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not inspect EC2 termination protection settings.",
                        "Verify AWS permissions and EC2 service availability."
                )
        );
    }

    return findings;
}

// =========================================================
// EC2 PUBLIC EBS SNAPSHOT EXPOSURE CHECK
// =========================================================

private List<SecurityFinding> scanPublicSnapshots() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("----------------------------------------");
    System.out.println("       EBS Public Snapshot Checks");
    System.out.println("----------------------------------------");

    try {

        DescribeSnapshotsResponse response =
                ec2Client.describeSnapshots(
                        DescribeSnapshotsRequest.builder()
                                .ownerIds("self")
                                .restorableByUserIds("all")
                                .build()
                );

        int publicSnapshotCount = 0;

        for (Snapshot snapshot : response.snapshots()) {

            String snapshotId = snapshot.snapshotId();

            publicSnapshotCount++;

            System.out.println(
                    "Snapshot: " + snapshotId
                            + " | Publicly Restorable [HIGH]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-EC2-006",
                            "EC2 Public EBS Snapshot - " + snapshotId,
                            "WARNING",
                            "HIGH",
                            "EBS snapshot " + snapshotId
                                    + " is publicly restorable.",
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
        }

        if (publicSnapshotCount == 0) {

            System.out.println(
                    "Public EBS Snapshots: NONE [PASS]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-EC2-006",
                            "EC2 Public EBS Snapshots",
                            "PASS",
                            "NONE",
                            "No publicly restorable EBS snapshots were detected.",
                            "No action required. Continue restricting EBS snapshot sharing."
                    )
            );
        }

        System.out.println(
                "Public EBS Snapshots Found: "
                        + publicSnapshotCount
        );

    } catch (Exception e) {

        System.out.println(
                "Public EBS snapshot scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-EC2-006",
                        "EC2 Public EBS Snapshot Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not inspect EBS snapshot sharing permissions.",
                        "Verify that CloudSentry has permission to describe EBS snapshots."
                )
        );
    }

    return findings;
}

// =========================================================
// EC2 UNENCRYPTED EBS SNAPSHOT CHECK
// =========================================================

private List<SecurityFinding> scanUnencryptedSnapshots() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("----------------------------------------");
    System.out.println("       EBS Snapshot Encryption Checks");
    System.out.println("----------------------------------------");

    try {

        DescribeSnapshotsResponse response =
                ec2Client.describeSnapshots(
                        DescribeSnapshotsRequest.builder()
                                .ownerIds("self")
                                .build()
                );

        int unencryptedSnapshotCount = 0;

        for (Snapshot snapshot : response.snapshots()) {

            String snapshotId = snapshot.snapshotId();

            if (!snapshot.encrypted()) {

                unencryptedSnapshotCount++;

                System.out.println(
                        "Snapshot: " + snapshotId
                                + " | UNENCRYPTED [MEDIUM]"
                );

                findings.add(
                        new SecurityFinding(
                                "CS-EC2-007",
                                "EC2 Unencrypted EBS Snapshot - " + snapshotId,
                                "WARNING",
                                "MEDIUM",
                                "EBS snapshot " + snapshotId
                                        + " is not encrypted.",
                                "Use encrypted EBS snapshots to protect stored data and reduce the risk of unauthorized data exposure."
                        )
                );
            }
        }

        if (unencryptedSnapshotCount == 0) {

            System.out.println(
                    "Unencrypted EBS Snapshots: NONE [PASS]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-EC2-007",
                            "EC2 Unencrypted EBS Snapshots",
                            "PASS",
                            "NONE",
                            "No unencrypted EBS snapshots were detected.",
                            "No action required. Continue using encryption for EBS snapshots."
                    )
            );
        }

        System.out.println(
                "Unencrypted EBS Snapshots Found: "
                        + unencryptedSnapshotCount
        );

    } catch (Exception e) {

        System.out.println(
                "EBS snapshot encryption scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-EC2-007",
                        "EC2 EBS Snapshot Encryption Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not inspect EBS snapshot encryption status.",
                        "Verify that CloudSentry has permission to describe EBS snapshots."
                )
        );
    }

    return findings;
}

// =========================================================
// EC2 PUBLIC SENSITIVE PORT EXPOSURE CHECK
// =========================================================

private List<SecurityFinding> scanSensitivePortExposure() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("----------------------------------------");
    System.out.println("       Sensitive Port Exposure Checks");
    System.out.println("----------------------------------------");

    try {

        DescribeSecurityGroupsResponse response =
                ec2Client.describeSecurityGroups(
                        DescribeSecurityGroupsRequest.builder()
                                .build()
                );

        int exposedPortCount = 0;

        for (var securityGroup : response.securityGroups()) {

            String groupId = securityGroup.groupId();

            for (IpPermission permission : securityGroup.ipPermissions()) {

                boolean publicAccess = false;

                for (IpRange range : permission.ipRanges()) {

                    if ("0.0.0.0/0".equals(range.cidrIp())) {
                        publicAccess = true;
                        break;
                    }
                }

                if (!publicAccess) {
                    continue;
                }

                String protocol = permission.ipProtocol();

                int fromPort =
                        permission.fromPort() == null
                                ? -1
                                : permission.fromPort();

                int toPort =
                        permission.toPort() == null
                                ? -1
                                : permission.toPort();

                int[] sensitivePorts = {
                        3389,   // RDP
                        3306,   // MySQL
                        5432,   // PostgreSQL
                        6379,   // Redis
                        9200,   // Elasticsearch
                        27017   // MongoDB
                };

                for (int port : sensitivePorts) {

                    boolean portExposed =
                            "-1".equals(protocol)
                            || (
                                fromPort != -1
                                && toPort != -1
                                && port >= fromPort
                                && port <= toPort
                            );

                    if (!portExposed) {
                        continue;
                    }

                    exposedPortCount++;

                    String serviceName = switch (port) {
                        case 3389 -> "RDP";
                        case 3306 -> "MySQL";
                        case 5432 -> "PostgreSQL";
                        case 6379 -> "Redis";
                        case 9200 -> "Elasticsearch";
                        case 27017 -> "MongoDB";
                        default -> "Sensitive Service";
                    };

                    System.out.println(
                            "Security Group: " + groupId
                                    + " | Port: " + port
                                    + " (" + serviceName + ")"
                                    + " | PUBLIC [HIGH]"
                    );

                    findings.add(
                            new SecurityFinding(
                                    "CS-EC2-008",
                                    "EC2 Public Sensitive Port - "
                                            + groupId + ":" + port,
                                    "WARNING",
                                    "HIGH",
                                    serviceName + " port " + port
                                            + " is publicly accessible from 0.0.0.0/0.",
                                    "Restrict access to trusted IP ranges or private networks and avoid exposing sensitive services directly to the internet."
                            )
                    );

                    break;
                }
            }
        }

        if (exposedPortCount == 0) {

            System.out.println(
                    "Public Sensitive Ports: NONE [PASS]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-EC2-008",
                            "EC2 Public Sensitive Ports",
                            "PASS",
                            "NONE",
                            "No sensitive service ports were found publicly accessible.",
                            "No action required. Continue restricting sensitive services to trusted networks."
                    )
            );
        }

        System.out.println(
                "Public Sensitive Port Exposures: "
                        + exposedPortCount
        );

    } catch (Exception e) {

        System.out.println(
                "Sensitive port exposure scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-EC2-008",
                        "EC2 Sensitive Port Exposure Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not inspect security group port exposure.",
                        "Verify that CloudSentry has permission to describe EC2 security groups."
                )
        );
    }

    return findings;
}

// =========================================================
// EC2 UNRESTRICTED OUTBOUND TRAFFIC CHECK
// =========================================================

private List<SecurityFinding> scanUnrestrictedOutboundTraffic() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("----------------------------------------");
    System.out.println("       Outbound Traffic Checks");
    System.out.println("----------------------------------------");

    try {

        DescribeSecurityGroupsResponse response =
                ec2Client.describeSecurityGroups(
                        DescribeSecurityGroupsRequest.builder()
                                .build()
                );

        int unrestrictedGroups = 0;

        for (var securityGroup : response.securityGroups()) {

            String groupId = securityGroup.groupId();

            for (IpPermission permission : securityGroup.ipPermissionsEgress()) {

                boolean unrestricted =
                        permission.ipRanges().stream()
                                .anyMatch(range ->
                                        "0.0.0.0/0".equals(range.cidrIp()));

                if (!unrestricted) {
                    continue;
                }

                unrestrictedGroups++;

                String protocol = permission.ipProtocol();

                System.out.println(
                        "Security Group: " + groupId
                                + " | Protocol: " + protocol
                                + " | Destination: 0.0.0.0/0"
                                + " [LOW]"
                );

                findings.add(
                        new SecurityFinding(
                                "CS-EC2-009",
                                "EC2 Unrestricted Outbound Traffic - " + groupId,
                                "WARNING",
                                "LOW",
                                "Security group " + groupId
                                        + " allows outbound traffic to 0.0.0.0/0.",
                                "Restrict outbound traffic to only the destinations and protocols required by the workload."
                        )
                );

                break;
            }
        }

        if (unrestrictedGroups == 0) {

            System.out.println(
                    "Unrestricted Outbound Traffic: NONE [PASS]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-EC2-009",
                            "EC2 Unrestricted Outbound Traffic",
                            "PASS",
                            "NONE",
                            "No security groups were detected with unrestricted outbound access.",
                            "No action required. Continue using least-privilege network egress rules."
                    )
            );
        }

        System.out.println(
                "Security Groups with Unrestricted Egress: "
                        + unrestrictedGroups
        );

    } catch (Exception e) {

        System.out.println(
                "Outbound traffic scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-EC2-009",
                        "EC2 Outbound Traffic Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not inspect security group outbound rules.",
                        "Verify that CloudSentry has permission to describe EC2 security groups."
                )
        );
    }

    return findings;
}

// =========================================================
// EC2 PUBLIC IPV6 EXPOSURE CHECK
// =========================================================

private List<SecurityFinding> scanIpv6Exposure() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("----------------------------------------");
    System.out.println("       IPv6 Exposure Checks");
    System.out.println("----------------------------------------");

    try {

        DescribeSecurityGroupsResponse response =
                ec2Client.describeSecurityGroups(
                        DescribeSecurityGroupsRequest.builder()
                                .build()
                );

        int exposedGroups = 0;

        for (var securityGroup : response.securityGroups()) {

            String groupId = securityGroup.groupId();

            for (IpPermission permission : securityGroup.ipPermissions()) {

                boolean publicIpv6 =
                        permission.ipv6Ranges().stream()
                                .anyMatch(range ->
                                        "::/0".equals(range.cidrIpv6()));

                if (!publicIpv6) {
                    continue;
                }

                exposedGroups++;

                String protocol = permission.ipProtocol();

                int fromPort =
                        permission.fromPort() == null
                                ? -1
                                : permission.fromPort();

                int toPort =
                        permission.toPort() == null
                                ? -1
                                : permission.toPort();

                String portDescription;

                if (fromPort == -1 && toPort == -1) {
                    portDescription = "ALL PORTS";
                } else if (fromPort == toPort) {
                    portDescription = String.valueOf(fromPort);
                } else {
                    portDescription =
                            fromPort + "-" + toPort;
                }

                System.out.println(
                        "Security Group: " + groupId
                                + " | Protocol: " + protocol
                                + " | Ports: " + portDescription
                                + " | IPv6: ::/0 [HIGH]"
                );

                findings.add(
                        new SecurityFinding(
                                "CS-EC2-010",
                                "EC2 Public IPv6 Access - " + groupId,
                                "WARNING",
                                "HIGH",
                                "Security group " + groupId
                                        + " allows inbound IPv6 traffic from the entire internet (::/0).",
                                "Restrict IPv6 access to trusted IPv6 CIDR ranges and expose only the ports required by the workload."
                        )
                );

                break;
            }
        }

        if (exposedGroups == 0) {

            System.out.println(
                    "Public IPv6 Access: NONE [PASS]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-EC2-010",
                            "EC2 Public IPv6 Access",
                            "PASS",
                            "NONE",
                            "No security groups were detected with inbound IPv6 access from ::/0.",
                            "No action required. Continue restricting inbound IPv6 traffic."
                    )
            );
        }

        System.out.println(
                "Security Groups with Public IPv6 Access: "
                        + exposedGroups
        );

    } catch (Exception e) {

        System.out.println(
                "IPv6 exposure scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-EC2-010",
                        "EC2 IPv6 Exposure Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not inspect IPv6 security group rules.",
                        "Verify that CloudSentry has permission to describe EC2 security groups."
                )
        );
    }

    return findings;
}

// =========================================================
// EC2 PUBLIC AMI EXPOSURE CHECK
// =========================================================

private List<SecurityFinding> scanPublicAmis() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("----------------------------------------");
    System.out.println("       Public AMI Exposure Checks");
    System.out.println("----------------------------------------");

    try {

        DescribeImagesResponse response =
                ec2Client.describeImages(
                        DescribeImagesRequest.builder()
                                .owners("self")
                                .filters(
                                        software.amazon.awssdk.services.ec2.model.Filter.builder()
                                                .name("is-public")
                                                .values("true")
                                                .build()
                                )
                                .build()
                );

        int publicAmiCount = 0;

        for (Image image : response.images()) {

            String imageId = image.imageId();
            String imageName = image.name();

            publicAmiCount++;

            System.out.println(
                    "AMI: " + imageId
                            + " | Name: " + imageName
                            + " | PUBLIC [HIGH]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-EC2-011",
                            "EC2 Public AMI - " + imageId,
                            "WARNING",
                            "HIGH",
                            "AMI " + imageId
                                    + " is publicly accessible and can be launched by other AWS users.",
                            "Remove public sharing from the AMI unless public distribution is explicitly required."
                    )
            );
        }

        if (publicAmiCount == 0) {

            System.out.println(
                    "Public AMIs: NONE [PASS]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-EC2-011",
                            "EC2 Public AMIs",
                            "PASS",
                            "NONE",
                            "No publicly accessible AMIs owned by this account were detected.",
                            "No action required. Continue restricting AMI launch permissions."
                    )
            );
        }

        System.out.println(
                "Public AMIs Found: "
                        + publicAmiCount
        );

    } catch (Exception e) {

        System.out.println(
                "Public AMI scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-EC2-011",
                        "EC2 Public AMI Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not inspect AMI public access.",
                        "Verify that CloudSentry has permission to describe EC2 images."
                )
        );
    }

    return findings;
}

// =========================================================
// EC2 UNENCRYPTED EBS VOLUME CHECK
// =========================================================

private List<SecurityFinding> scanUnencryptedVolumes() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("----------------------------------------");
    System.out.println("       EBS Volume Encryption Checks");
    System.out.println("----------------------------------------");

    try {

        DescribeVolumesResponse response =
                ec2Client.describeVolumes(
                        DescribeVolumesRequest.builder()
                                .build()
                );

        int unencryptedVolumeCount = 0;

        for (Volume volume : response.volumes()) {

            String volumeId = volume.volumeId();

            if (!volume.encrypted()) {

                unencryptedVolumeCount++;

                System.out.println(
                        "Volume: " + volumeId
                                + " | UNENCRYPTED [HIGH]"
                );

                findings.add(
                        new SecurityFinding(
                                "CS-EC2-012",
                                "EC2 Unencrypted EBS Volume - " + volumeId,
                                "WARNING",
                                "HIGH",
                                "EBS volume " + volumeId
                                        + " is not encrypted.",
                                "Enable encryption for the EBS volume and use encrypted volumes for sensitive workloads."
                        )
                );
            }
        }

        if (unencryptedVolumeCount == 0) {

            System.out.println(
                    "Unencrypted EBS Volumes: NONE [PASS]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-EC2-012",
                            "EC2 Unencrypted EBS Volumes",
                            "PASS",
                            "NONE",
                            "No unencrypted EBS volumes were detected.",
                            "No action required. Continue using encryption for EBS volumes."
                    )
            );
        }

        System.out.println(
                "Unencrypted EBS Volumes Found: "
                        + unencryptedVolumeCount
        );

    } catch (Exception e) {

        System.out.println(
                "EBS volume encryption scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-EC2-012",
                        "EC2 EBS Volume Encryption Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not inspect EBS volume encryption status.",
                        "Verify that CloudSentry has permission to describe EBS volumes."
                )
        );
    }

    return findings;
}

    private String getServiceName(int port) {

        switch (port) {

            case 22:
                return "SSH";

            case 3389:
                return "RDP";

            case 3306:
                return "MySQL";

            case 5432:
                return "PostgreSQL";

            case 6379:
                return "Redis";

            case 27017:
                return "MongoDB";

            case 80:
                return "HTTP";

            case 443:
                return "HTTPS";

            default:
                return "TCP";
        }
    }

    // =========================================================
    // SEVERITY
    // =========================================================

    private String getSeverity(int port) {

        switch (port) {

            case 22:
            case 3389:
            case 3306:
            case 5432:
            case 6379:
            case 27017:
                return "HIGH";

            case 80:
            case 443:
                return "LOW";

            default:
                return "MEDIUM";
        }
    }

    // =========================================================
    // RECOMMENDATION
    // =========================================================

    private String getRecommendation(int port) {

        switch (port) {

            case 22:
                return "Restrict SSH access to trusted IP addresses or VPN networks.";

            case 3389:
                return "Restrict RDP access to trusted IP addresses or VPN networks.";

            case 3306:
                return "Do not expose MySQL directly to the internet. Restrict access to application servers.";

            case 5432:
                return "Do not expose PostgreSQL directly to the internet. Restrict access to trusted application servers.";

            case 6379:
                return "Do not expose Redis directly to the internet. Restrict access to trusted application servers.";

            case 27017:
                return "Do not expose MongoDB directly to the internet. Restrict access to trusted application servers.";

            case 80:
                return "Consider redirecting HTTP traffic to HTTPS and restricting unnecessary public access.";

            case 443:
                return "HTTPS is normally acceptable for public services. Ensure the application is securely configured.";

            default:
                return "Restrict publicly accessible ports to only those required by the application.";
        }
    }
}