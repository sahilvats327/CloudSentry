package myapp.scanner;

import myapp.config.AwsClientFactory;
import myapp.model.SecurityFinding;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeAddressesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeAddressesResponse;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesResponse;
import software.amazon.awssdk.services.ec2.model.DescribeVolumesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeVolumesResponse;
import software.amazon.awssdk.services.ec2.model.Instance;
import software.amazon.awssdk.services.ec2.model.Volume;
import software.amazon.awssdk.services.cloudtrail.CloudTrailClient;
import software.amazon.awssdk.services.cloudtrail.model.LookupAttribute;
import software.amazon.awssdk.services.cloudtrail.model.LookupAttributeKey;
import software.amazon.awssdk.services.cloudtrail.model.LookupEventsRequest;
import software.amazon.awssdk.services.cloudtrail.model.LookupEventsResponse;


import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;



@Component
public class CostSecurityScanner {

    private Ec2Client ec2Client;
private CloudTrailClient cloudTrailClient;
private final AwsClientFactory awsClientFactory;

    @Value("${cloudsentry.cost.stopped-instance-days:30}")
    private int stoppedInstanceDays;

    public CostSecurityScanner(
        Ec2Client ec2Client,
        AwsClientFactory awsClientFactory) {

    this.ec2Client = ec2Client;
    this.awsClientFactory = awsClientFactory;
}

    public List<SecurityFinding> scan(String region) {

       if (region != null && !region.isBlank()) {

    ec2Client =
            awsClientFactory.createEc2Client(region);

    cloudTrailClient =
            CloudTrailClient.builder()
                    .region(
                            software.amazon.awssdk.regions.Region.of(region)
                    )
                    .build();
}

        List<SecurityFinding> findings = new ArrayList<>();

        System.out.println();
        System.out.println("========================================");
        System.out.println("          COST OPTIMIZATION SCAN");
        System.out.println("========================================");

        findings.addAll(scanUnattachedVolumes());
        findings.addAll(scanUnusedElasticIps());
        findings.addAll(scanLongStoppedInstances());

        return findings;
    }

    /**
     * CS-COST-001
     *
     * Detects EBS volumes that are not attached to any EC2 instance.
     */
    private List<SecurityFinding> scanUnattachedVolumes() {

        List<SecurityFinding> findings = new ArrayList<>();

        System.out.println();
        System.out.println("----------------------------------------");
        System.out.println("       Unattached EBS Volumes");
        System.out.println("----------------------------------------");

        try {

            DescribeVolumesResponse response =
                    ec2Client.describeVolumes(
                            DescribeVolumesRequest.builder()
                                    .build()
                    );

            int checkedVolumes = 0;
            int unattachedVolumes = 0;

            for (Volume volume : response.volumes()) {

                checkedVolumes++;

                String volumeId = volume.volumeId();

                if (volumeId == null || volumeId.isBlank()) {
                    continue;
                }

                boolean attached = volume.attachments() != null
                        && !volume.attachments().isEmpty();

                if (!attached) {

                    unattachedVolumes++;

                    System.out.println(
                            "Volume: " + volumeId
                                    + " | State: " + volume.stateAsString()
                                    + " | UNATTACHED [MEDIUM]"
                    );

                    findings.add(
                            new SecurityFinding(
                                    "CS-COST-001",
                                    "Unattached EBS Volume - " + volumeId,
                                    "WARNING",
                                    "MEDIUM",
                                    "EBS volume " + volumeId
                                            + " is not attached to any EC2 instance and may continue generating storage costs.",
                                    "Review the volume and delete it if it is no longer required. Create a snapshot first if the data must be retained."
                            )
                    );

                } else {

                    System.out.println(
                            "Volume: " + volumeId
                                    + " | ATTACHED [PASS]"
                    );

                    findings.add(
                            new SecurityFinding(
                                    "CS-COST-001",
                                    "EBS Volume - " + volumeId,
                                    "PASS",
                                    "NONE",
                                    "EBS volume " + volumeId
                                            + " is attached to an EC2 instance.",
                                    "No action required."
                            )
                    );
                }
            }

            System.out.println();
            System.out.println("Volumes Checked: " + checkedVolumes);
            System.out.println("Unattached Volumes: " + unattachedVolumes);

        } catch (Exception e) {

            System.out.println(
                    "Unattached EBS volume scan failed: "
                            + e.getMessage()
            );

            findings.add(
                    new SecurityFinding(
                            "CS-COST-001",
                            "Unattached EBS Volume Scan",
                            "ERROR",
                            "HIGH",
                            "CloudSentry could not determine whether EBS volumes are attached to EC2 instances.",
                            "Verify AWS permissions for describing EBS volumes and retry the scan."
                    )
            );
        }

        return findings;
    }

    /**
 * CS-COST-002
 *
 * Detects Elastic IP addresses that are:
 * - not associated with an EC2 instance
 * - associated with a stopped EC2 instance
 *
 * An Elastic IP attached to a running instance is considered
 * actively used and therefore passes this cost check.
 */
private List<SecurityFinding> scanUnusedElasticIps() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("----------------------------------------");
    System.out.println("          Elastic IP Checks");
    System.out.println("----------------------------------------");

    try {

        /*
         * Load EC2 instances once so that we can determine
         * whether an Elastic IP's associated instance is
         * currently running or stopped.
         */
        DescribeInstancesResponse instancesResponse =
                ec2Client.describeInstances(
                        DescribeInstancesRequest.builder()
                                .build()
                );

        java.util.Map<String, String> instanceStates =
                new java.util.HashMap<>();

        for (var reservation : instancesResponse.reservations()) {

            for (Instance instance : reservation.instances()) {

                String instanceId = instance.instanceId();

                if (instanceId == null || instanceId.isBlank()) {
                    continue;
                }

                if (instance.state() == null) {
                    continue;
                }

                instanceStates.put(
                        instanceId,
                        instance.state().nameAsString()
                );
            }
        }

        DescribeAddressesResponse response =
                ec2Client.describeAddresses(
                        DescribeAddressesRequest.builder()
                                .build()
                );

        int checkedAddresses = 0;
        int unusedAddresses = 0;
        int stoppedInstanceAddresses = 0;

        for (var address : response.addresses()) {

            checkedAddresses++;

            String publicIp = address.publicIp();

            if (publicIp == null || publicIp.isBlank()) {
                continue;
            }

            String instanceId = address.instanceId();

            /*
             * Case 1:
             * Elastic IP is not associated with any EC2 instance.
             */
            if (instanceId == null || instanceId.isBlank()) {

                unusedAddresses++;

                System.out.println(
                        "Elastic IP: " + publicIp
                                + " | NOT ASSOCIATED [MEDIUM]"
                );

                findings.add(
                        new SecurityFinding(
                                "CS-COST-002",
                                "Unused Elastic IP - " + publicIp,
                                "WARNING",
                                "MEDIUM",
                                "Elastic IP " + publicIp
                                        + " is not associated with any EC2 instance and may generate unnecessary AWS charges.",
                                "Release the Elastic IP if it is no longer required."
                        )
                );

                continue;
            }

            /*
             * Case 2:
             * Elastic IP is associated with an EC2 instance.
             */
            String state = instanceStates.get(instanceId);

            /*
             * If the instance is stopped, the EIP may no longer
             * be necessary and can still contribute to cost.
             */
            if ("stopped".equalsIgnoreCase(state)) {

                stoppedInstanceAddresses++;

                System.out.println(
                        "Elastic IP: " + publicIp
                                + " | Instance: " + instanceId
                                + " | INSTANCE STOPPED [MEDIUM]"
                );

                findings.add(
                        new SecurityFinding(
                                "CS-COST-002",
                                "Elastic IP on Stopped Instance - "
                                        + publicIp,
                                "WARNING",
                                "MEDIUM",
                                "Elastic IP " + publicIp
                                        + " is associated with stopped EC2 instance "
                                        + instanceId
                                        + " and may be generating unnecessary AWS charges.",
                                "Review whether the stopped instance and its Elastic IP are still required. Release the Elastic IP if it is no longer needed."
                        )
                );

            } else {

                /*
                 * Running instance or another valid active state.
                 */
                System.out.println(
                        "Elastic IP: " + publicIp
                                + " | Instance: "
                                + instanceId
                                + " [PASS]"
                );

                findings.add(
                        new SecurityFinding(
                                "CS-COST-002",
                                "Elastic IP - " + publicIp,
                                "PASS",
                                "NONE",
                                "Elastic IP " + publicIp
                                        + " is associated with EC2 instance "
                                        + instanceId
                                        + ".",
                                "No action required."
                        )
                );
            }
        }

        System.out.println();
        System.out.println(
                "Elastic IPs Checked: "
                        + checkedAddresses
        );

        System.out.println(
                "Unused Elastic IPs: "
                        + unusedAddresses
        );

        System.out.println(
                "Elastic IPs on Stopped Instances: "
                        + stoppedInstanceAddresses
        );

    } catch (Exception e) {

        System.out.println(
                "Elastic IP scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-COST-002",
                        "Elastic IP Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not determine whether Elastic IP addresses are in use.",
                        "Verify AWS permissions for describing Elastic IP addresses and EC2 instances, then retry the scan."
                )
        );
    }

    return findings;
}

/**
 * CS-COST-003
 *
 * Detects EC2 instances that have remained stopped for an
 * extended period.
 *
 * CloudTrail is used to determine the most recent StopInstances
 * event instead of parsing EC2 stateTransitionReason text.
 *
 * If CloudTrail cannot provide a matching stop event, CloudSentry
 * does NOT classify the instance as PASS. The duration is treated
 * as unavailable.
 */
private List<SecurityFinding> scanLongStoppedInstances() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("----------------------------------------");
    System.out.println("       Long-Stopped EC2 Instances");
    System.out.println("----------------------------------------");

    try {

        DescribeInstancesResponse response =
                ec2Client.describeInstances(
                        DescribeInstancesRequest.builder()
                                .build()
                );

        int checkedInstances = 0;
        int stoppedInstances = 0;
        int extendedStoppedInstances = 0;
        int unavailableStopTimes = 0;

        for (var reservation : response.reservations()) {

            for (Instance instance : reservation.instances()) {

                checkedInstances++;

                String instanceId =
                        instance.instanceId();

                if (instanceId == null
                        || instanceId.isBlank()) {
                    continue;
                }

                if (instance.state() == null
                        || instance.state().name()
                        != software.amazon.awssdk.services.ec2.model.InstanceStateName.STOPPED) {
                    continue;
                }

                stoppedInstances++;

                Instant stoppedAt =
                        findLastStopEvent(instanceId);

                /*
                 * CloudTrail could not provide a matching
                 * StopInstances event.
                 *
                 * Do not classify this as PASS because the
                 * actual stopped duration cannot be verified.
                 */
                if (stoppedAt == null) {

                    unavailableStopTimes++;

                    System.out.println(
                            "Instance: " + instanceId
                                    + " | STOPPED"
                                    + " | Stop time unavailable [INFO]"
                    );

                    findings.add(
                            new SecurityFinding(
                                    "CS-COST-003",
                                    "Stopped EC2 Instance - "
                                            + instanceId,
                                    "INFO",
                                    "LOW",
                                    "EC2 instance "
                                            + instanceId
                                            + " is currently stopped, but CloudSentry could not determine when it was stopped because no matching recent CloudTrail StopInstances event was available.",
                                    "Review the instance manually. CloudTrail LookupEvents provides only recent management-event history; use a longer-term event source such as CloudTrail Lake, AWS Config, or previously retained CloudTrail logs when historical stop duration is required."
                            )
                    );

                    continue;
                }

                long stoppedDays =
                        Duration.between(
                                stoppedAt,
                                Instant.now()
                        ).toDays();

                if (stoppedDays >= stoppedInstanceDays) {

                    extendedStoppedInstances++;

                    System.out.println(
                            "Instance: " + instanceId
                                    + " | Stopped: "
                                    + stoppedDays
                                    + " days"
                                    + " | EXTENDED [MEDIUM]"
                    );

                    findings.add(
                            new SecurityFinding(
                                    "CS-COST-003",
                                    "Long-Stopped EC2 Instance - "
                                            + instanceId,
                                    "WARNING",
                                    "MEDIUM",
                                    "EC2 instance "
                                            + instanceId
                                            + " has remained stopped for approximately "
                                            + stoppedDays
                                            + " days based on its most recent CloudTrail StopInstances event.",
                                    "Review the instance and terminate it if it is no longer required. Preserve required data or AMIs before termination."
                            )
                    );

                } else {

                    System.out.println(
                            "Instance: " + instanceId
                                    + " | Stopped: "
                                    + stoppedDays
                                    + " days [PASS]"
                    );

                    findings.add(
                            new SecurityFinding(
                                    "CS-COST-003",
                                    "Stopped EC2 Instance - "
                                            + instanceId,
                                    "PASS",
                                    "NONE",
                                    "EC2 instance "
                                            + instanceId
                                            + " has been stopped for approximately "
                                            + stoppedDays
                                            + " days based on its most recent CloudTrail StopInstances event, which is below the configured threshold of "
                                            + stoppedInstanceDays
                                            + " days.",
                                    "No action required."
                            )
                    );
                }
            }
        }

        System.out.println();
        System.out.println(
                "Instances Checked: "
                        + checkedInstances
        );

        System.out.println(
                "Stopped Instances: "
                        + stoppedInstances
        );

        System.out.println(
                "Extended Stopped Instances: "
                        + extendedStoppedInstances
        );

        System.out.println(
                "Stop Times Unavailable: "
                        + unavailableStopTimes
        );

        System.out.println(
                "Configured Threshold: "
                        + stoppedInstanceDays
                        + " days"
        );

    } catch (Exception e) {

        System.out.println(
                "Long-stopped EC2 instance scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-COST-003",
                        "Long-Stopped EC2 Instance Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not determine whether stopped EC2 instances have remained stopped for an extended period using EC2 and CloudTrail data.",
                        "Verify AWS permissions for describing EC2 instances and looking up CloudTrail events, then retry the scan."
                )
        );
    }

    return findings;
}

/**
 * Finds the most recent StopInstances event for an EC2 instance.
 *
 * CloudTrail LookupEvents returns events in reverse chronological
 * order, so the first matching StopInstances event is the most
 * recent one.
 *
 * Returns null when the lookup succeeds but no matching event
 * is available in the accessible CloudTrail history.
 *
 * Throws an exception when the CloudTrail API request itself fails.
 */
private Instant findLastStopEvent(String instanceId) {

    if (cloudTrailClient == null) {
        return null;
    }

    LookupAttribute lookupAttribute =
            LookupAttribute.builder()
                    .attributeKey(
                            LookupAttributeKey.RESOURCE_NAME
                    )
                    .attributeValue(instanceId)
                    .build();

    LookupEventsRequest request =
            LookupEventsRequest.builder()
                    .lookupAttributes(
                            lookupAttribute
                    )
                    .maxResults(50)
                    .build();

    LookupEventsResponse response =
            cloudTrailClient.lookupEvents(request);

    for (var event : response.events()) {

        if (!"StopInstances".equalsIgnoreCase(
                event.eventName())) {
            continue;
        }

        if (event.eventTime() != null) {
            return event.eventTime();
        }
    }

    return null;
}
    
}