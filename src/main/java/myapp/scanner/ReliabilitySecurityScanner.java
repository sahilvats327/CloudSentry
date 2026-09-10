package myapp.scanner;

import myapp.config.AwsClientFactory;
import myapp.model.SecurityFinding;

import org.springframework.stereotype.Component;

import software.amazon.awssdk.services.autoscaling.AutoScalingClient;
import software.amazon.awssdk.services.autoscaling.model.AutoScalingInstanceDetails;
import software.amazon.awssdk.services.autoscaling.model.DescribeAutoScalingInstancesRequest;
import software.amazon.awssdk.services.autoscaling.model.DescribeAutoScalingInstancesResponse;

import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesResponse;
import software.amazon.awssdk.services.ec2.model.Instance;

import software.amazon.awssdk.services.rds.RdsClient;
import software.amazon.awssdk.services.rds.model.DBInstance;
import software.amazon.awssdk.services.rds.model.DescribeDbInstancesRequest;
import software.amazon.awssdk.services.rds.model.DescribeDbInstancesResponse;

import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetBucketLifecycleConfigurationRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
public class ReliabilitySecurityScanner {

    private Ec2Client ec2Client;
    private RdsClient rdsClient;
    private S3Client s3Client;
    private AutoScalingClient autoScalingClient;

    private final AwsClientFactory awsClientFactory;

    public ReliabilitySecurityScanner(
            Ec2Client ec2Client,
            RdsClient rdsClient,
            S3Client s3Client,
            AwsClientFactory awsClientFactory) {

        this.ec2Client = ec2Client;
        this.rdsClient = rdsClient;
        this.s3Client = s3Client;
        this.awsClientFactory = awsClientFactory;
    }

    public List<SecurityFinding> scan(String region) {

        if (region != null && !region.isBlank()) {

            ec2Client =
                    awsClientFactory.createEc2Client(region);

            rdsClient =
                    awsClientFactory.createRdsClient(region);

            s3Client =
                    awsClientFactory.createS3Client(region);

            autoScalingClient =
                    AutoScalingClient.builder()
                            .region(
                                    software.amazon.awssdk.regions.Region.of(region)
                            )
                            .build();
        }

        List<SecurityFinding> findings = new ArrayList<>();

        System.out.println();
        System.out.println("========================================");
        System.out.println("          RELIABILITY SCAN");
        System.out.println("========================================");

        findings.addAll(scanRdsMultiAz());
        findings.addAll(scanS3Lifecycle());
        findings.addAll(scanEc2AutoScaling());

        return findings;
    }

    /**
     * CS-REL-001
     *
     * Detects RDS instances without Multi-AZ enabled.
     */
    private List<SecurityFinding> scanRdsMultiAz() {

        List<SecurityFinding> findings = new ArrayList<>();

        System.out.println();
        System.out.println("----------------------------------------");
        System.out.println("       RDS Multi-AZ Checks");
        System.out.println("----------------------------------------");

        try {

            DescribeDbInstancesResponse response =
                    rdsClient.describeDBInstances(
                            DescribeDbInstancesRequest.builder()
                                    .build()
                    );

            int checkedInstances = 0;
            int multiAzDisabled = 0;

            for (DBInstance dbInstance : response.dbInstances()) {

                checkedInstances++;

                String identifier =
                        dbInstance.dbInstanceIdentifier();

                if (identifier == null || identifier.isBlank()) {
                    continue;
                }

                if (!Boolean.TRUE.equals(dbInstance.multiAZ())) {

                    multiAzDisabled++;

                    System.out.println(
                            "RDS: " + identifier
                                    + " | Multi-AZ DISABLED [MEDIUM]"
                    );

                    findings.add(
                            new SecurityFinding(
                                    "CS-REL-001",
                                    "RDS Multi-AZ Disabled - " + identifier,
                                    "WARNING",
                                    "MEDIUM",
                                    "RDS instance " + identifier
                                            + " does not have Multi-AZ deployment enabled, reducing availability during an Availability Zone failure.",
                                    "Enable Multi-AZ deployment for production RDS workloads that require high availability."
                            )
                    );

                } else {

                    System.out.println(
                            "RDS: " + identifier
                                    + " | Multi-AZ ENABLED [PASS]"
                    );

                    findings.add(
                            new SecurityFinding(
                                    "CS-REL-001",
                                    "RDS Multi-AZ - " + identifier,
                                    "PASS",
                                    "NONE",
                                    "RDS instance " + identifier
                                            + " has Multi-AZ deployment enabled.",
                                    "No action required."
                            )
                    );
                }
            }

            System.out.println();
            System.out.println(
                    "RDS Instances Checked: "
                            + checkedInstances
            );

            System.out.println(
                    "Multi-AZ Disabled: "
                            + multiAzDisabled
            );

        } catch (Exception e) {

            System.out.println(
                    "RDS Multi-AZ scan failed: "
                            + e.getMessage()
            );

            findings.add(
                    new SecurityFinding(
                            "CS-REL-001",
                            "RDS Multi-AZ Scan",
                            "ERROR",
                            "HIGH",
                            "CloudSentry could not determine the Multi-AZ configuration of RDS instances.",
                            "Verify AWS permissions for describing RDS instances and retry the scan."
                    )
            );
        }

        return findings;
    }

    /**
     * CS-REL-002
     *
     * Detects S3 buckets without lifecycle policies.
     */
    private List<SecurityFinding> scanS3Lifecycle() {

        List<SecurityFinding> findings = new ArrayList<>();

        System.out.println();
        System.out.println("----------------------------------------");
        System.out.println("       S3 Lifecycle Checks");
        System.out.println("----------------------------------------");

        try {

            var bucketsResponse =
                    s3Client.listBuckets();

            int checkedBuckets = 0;
            int missingLifecycle = 0;

            for (var bucket : bucketsResponse.buckets()) {

                String bucketName = bucket.name();

                if (bucketName == null || bucketName.isBlank()) {
                    continue;
                }

                checkedBuckets++;

                try {

                    var lifecycleResponse =
                            s3Client.getBucketLifecycleConfiguration(
                                    GetBucketLifecycleConfigurationRequest.builder()
                                            .bucket(bucketName)
                                            .build()
                            );

                    if (lifecycleResponse.rules() == null
                            || lifecycleResponse.rules().isEmpty()) {

                        missingLifecycle++;

                        System.out.println(
                                "S3: " + bucketName
                                        + " | NO LIFECYCLE POLICY [MEDIUM]"
                        );

                        findings.add(
                                new SecurityFinding(
                                        "CS-REL-002",
                                        "S3 Lifecycle Policy Missing - "
                                                + bucketName,
                                        "WARNING",
                                        "MEDIUM",
                                        "S3 bucket " + bucketName
                                                + " does not have a lifecycle policy configured.",
                                        "Configure an appropriate S3 lifecycle policy to transition or expire objects according to the workload's retention requirements."
                                )
                        );

                    } else {

                        System.out.println(
                                "S3: " + bucketName
                                        + " | LIFECYCLE CONFIGURED [PASS]"
                        );

                        findings.add(
                                new SecurityFinding(
                                        "CS-REL-002",
                                        "S3 Lifecycle Policy - "
                                                + bucketName,
                                        "PASS",
                                        "NONE",
                                        "S3 bucket " + bucketName
                                                + " has a lifecycle policy configured.",
                                        "No action required."
                                )
                        );
                    }

                } catch (S3Exception e) {

                    missingLifecycle++;

                    System.out.println(
                            "S3: " + bucketName
                                    + " | NO LIFECYCLE POLICY [MEDIUM]"
                    );

                    findings.add(
                            new SecurityFinding(
                                    "CS-REL-002",
                                    "S3 Lifecycle Policy Missing - "
                                            + bucketName,
                                    "WARNING",
                                    "MEDIUM",
                                    "S3 bucket " + bucketName
                                            + " does not have a lifecycle policy configured.",
                                    "Configure an appropriate S3 lifecycle policy to transition or expire objects according to the workload's retention requirements."
                            )
                    );
                }
            }

            System.out.println();
            System.out.println(
                    "S3 Buckets Checked: "
                            + checkedBuckets
            );

            System.out.println(
                    "Buckets Without Lifecycle: "
                            + missingLifecycle
            );

        } catch (Exception e) {

            System.out.println(
                    "S3 lifecycle scan failed: "
                            + e.getMessage()
            );

            findings.add(
                    new SecurityFinding(
                            "CS-REL-002",
                            "S3 Lifecycle Scan",
                            "ERROR",
                            "HIGH",
                            "CloudSentry could not determine whether S3 buckets have lifecycle policies configured.",
                            "Verify AWS permissions for listing buckets and reading lifecycle configurations, then retry the scan."
                    )
            );
        }

        return findings;
    }

    /**
     * CS-REL-003
     *
     * Detects EC2 instances that are not members of
     * an Auto Scaling Group.
     */
    private List<SecurityFinding> scanEc2AutoScaling() {

        List<SecurityFinding> findings = new ArrayList<>();

        System.out.println();
        System.out.println("----------------------------------------");
        System.out.println("       EC2 Auto Scaling Checks");
        System.out.println("----------------------------------------");

        try {

            DescribeInstancesResponse instancesResponse =
                    ec2Client.describeInstances(
                            DescribeInstancesRequest.builder()
                                    .build()
                    );

            DescribeAutoScalingInstancesResponse asgResponse =
                    autoScalingClient.describeAutoScalingInstances(
                            DescribeAutoScalingInstancesRequest.builder()
                                    .build()
                    );

            Set<String> autoscalingInstanceIds =
                    new HashSet<>();

            for (AutoScalingInstanceDetails asgInstance
                    : asgResponse.autoScalingInstances()) {

                if (asgInstance.instanceId() != null
                        && !asgInstance.instanceId().isBlank()) {

                    autoscalingInstanceIds.add(
                            asgInstance.instanceId()
                    );
                }
            }

            int checkedInstances = 0;
            int notInAutoScaling = 0;

            for (var reservation : instancesResponse.reservations()) {

                for (Instance instance
                        : reservation.instances()) {

                    String instanceId =
                            instance.instanceId();

                    if (instanceId == null
                            || instanceId.isBlank()) {
                        continue;
                    }

                    checkedInstances++;

                    if (!autoscalingInstanceIds.contains(instanceId)) {

                        notInAutoScaling++;

                        System.out.println(
                                "EC2: " + instanceId
                                        + " | NOT IN ASG [MEDIUM]"
                        );

                        findings.add(
                                new SecurityFinding(
                                        "CS-REL-003",
                                        "EC2 Instance Not in Auto Scaling Group - "
                                                + instanceId,
                                        "WARNING",
                                        "MEDIUM",
                                        "EC2 instance " + instanceId
                                                + " is not currently a member of an Auto Scaling Group.",
                                        "For workloads requiring high availability and automatic recovery, consider placing the instance in an appropriate Auto Scaling Group."
                                )
                        );

                    } else {

                        System.out.println(
                                "EC2: " + instanceId
                                        + " | IN ASG [PASS]"
                        );

                        findings.add(
                                new SecurityFinding(
                                        "CS-REL-003",
                                        "EC2 Auto Scaling Group - "
                                                + instanceId,
                                        "PASS",
                                        "NONE",
                                        "EC2 instance " + instanceId
                                                + " is a member of an Auto Scaling Group.",
                                        "No action required."
                                )
                        );
                    }
                }
            }

            System.out.println();
            System.out.println(
                    "EC2 Instances Checked: "
                            + checkedInstances
            );

            System.out.println(
                    "Instances Not in Auto Scaling: "
                            + notInAutoScaling
            );

        } catch (Exception e) {

            System.out.println(
                    "EC2 Auto Scaling scan failed: "
                            + e.getMessage()
            );

            findings.add(
                    new SecurityFinding(
                            "CS-REL-003",
                            "EC2 Auto Scaling Scan",
                            "ERROR",
                            "HIGH",
                            "CloudSentry could not determine whether EC2 instances belong to Auto Scaling Groups.",
                            "Verify AWS permissions for describing EC2 and Auto Scaling instances, then retry the scan."
                    )
            );
        }

        return findings;
    }
}