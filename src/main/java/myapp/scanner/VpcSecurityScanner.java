package myapp.scanner;

import myapp.config.AwsClientFactory;
import myapp.model.SecurityFinding;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.ec2.model.DescribeVpcsRequest;
import software.amazon.awssdk.services.ec2.model.DescribeVpcsResponse;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeRouteTablesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeRouteTablesResponse;
import software.amazon.awssdk.services.ec2.model.Route;
import software.amazon.awssdk.services.ec2.model.RouteTable;
import software.amazon.awssdk.services.ec2.model.DescribeInternetGatewaysRequest;
import software.amazon.awssdk.services.ec2.model.DescribeInternetGatewaysResponse;
import software.amazon.awssdk.services.ec2.model.InternetGateway;
import software.amazon.awssdk.services.ec2.model.DescribeSecurityGroupsRequest;
import software.amazon.awssdk.services.ec2.model.DescribeSecurityGroupsResponse;
import software.amazon.awssdk.services.ec2.model.IpPermission;
import software.amazon.awssdk.services.ec2.model.DescribeNetworkAclsRequest;
import software.amazon.awssdk.services.ec2.model.DescribeNetworkAclsResponse;
import software.amazon.awssdk.services.ec2.model.NetworkAcl;
import software.amazon.awssdk.services.ec2.model.DescribeFlowLogsRequest;
import software.amazon.awssdk.services.ec2.model.DescribeFlowLogsResponse;


import java.util.ArrayList;
import java.util.List;

@Component
public class VpcSecurityScanner implements SecurityScanner {

   
private Ec2Client ec2Client;
private final AwsClientFactory awsClientFactory;

public VpcSecurityScanner(
        Ec2Client ec2Client,
        AwsClientFactory awsClientFactory) {

    this.ec2Client = ec2Client;
    this.awsClientFactory = awsClientFactory;
}

   @Override
public List<SecurityFinding> scan(String region) {

    if (region == null || region.isBlank()) {
        region = "ap-south-1";
    }

    ec2Client = awsClientFactory.createEc2Client(region);

    List<SecurityFinding> findings = new ArrayList<>();

        System.out.println();
        System.out.println("----------------------------------------");
        System.out.println("       VPC Security Checks");
        System.out.println("----------------------------------------");

        findings.addAll(scanPublicSubnets());
        findings.addAll(scanInternetGateways());
        findings.addAll(scanDefaultSecurityGroups());
        findings.addAll(scanNetworkAclExposure());
        findings.addAll(scanFlowLogs());
        findings.addAll(scanPublicIpv6Routes());

        return findings;
    }

 // =========================================================
// VPC PUBLIC SUBNET EXPOSURE CHECK
// =========================================================

private List<SecurityFinding> scanPublicSubnets() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("Public Subnet Exposure Checks");

    try {

        DescribeRouteTablesResponse routeTableResponse =
                ec2Client.describeRouteTables(
                        DescribeRouteTablesRequest.builder()
                                .build()
                );

        int publicSubnetCount = 0;

        for (RouteTable routeTable :
                routeTableResponse.routeTables()) {

            boolean internetGatewayRoute = false;

            for (Route route : routeTable.routes()) {

                boolean ipv4InternetRoute =
                        "0.0.0.0/0".equals(
                                route.destinationCidrBlock()
                        );

                boolean activeInternetGatewayRoute =
                        route.gatewayId() != null
                        && route.gatewayId().startsWith("igw-")
                        && "active".equalsIgnoreCase(
                                route.stateAsString()
                        );

                if (ipv4InternetRoute
                        && activeInternetGatewayRoute) {

                    internetGatewayRoute = true;
                    break;
                }
            }

            if (!internetGatewayRoute) {
                continue;
            }

            String routeTableId =
                    routeTable.routeTableId();

            boolean subnetFound = false;

            for (var association :
                    routeTable.associations()) {

                if (association.subnetId() == null) {
                    continue;
                }

                subnetFound = true;

                String subnetId =
                        association.subnetId();

                System.out.println(
                        "Subnet: " + subnetId
                                + " | Route Table: "
                                + routeTableId
                                + " | PUBLIC [MEDIUM]"
                );

                findings.add(
                        new SecurityFinding(
                                "CS-VPC-001",
                                "VPC Public Subnet - "
                                        + subnetId,
                                "WARNING",
                                "MEDIUM",
                                "Subnet " + subnetId
                                        + " uses route table "
                                        + routeTableId
                                        + " with an active IPv4 default route to an Internet Gateway.",
                                "Keep sensitive workloads in private subnets and expose only resources that require direct internet connectivity."
                        )
                );

                publicSubnetCount++;
            }

            /*
             * If there is no explicit subnet association,
             * this may be the VPC's main route table.
             * Report the route table itself rather than falsely
             * claiming a specific subnet is public.
             */
            if (!subnetFound) {

                boolean mainRouteTable = routeTable.associations()
                        .stream()
                        .anyMatch(association ->
                                association.main()
                        );

                if (mainRouteTable) {

                    System.out.println(
                            "Main Route Table: " + routeTableId
                                    + " | Public Route Detected [MEDIUM]"
                    );

                    findings.add(
                            new SecurityFinding(
                                    "CS-VPC-001",
                                    "VPC Public Main Route Table - "
                                            + routeTableId,
                                    "WARNING",
                                    "MEDIUM",
                                    "The VPC main route table "
                                            + routeTableId
                                            + " contains an active IPv4 default route to an Internet Gateway.",
                                    "Review the subnets using the main route table and ensure sensitive workloads do not receive unintended internet routing."
                            )
                    );

                    publicSubnetCount++;
                }
            }
        }

        if (publicSubnetCount == 0) {

            System.out.println(
                    "Public Subnets: NONE [PASS]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-VPC-001",
                            "VPC Public Subnets",
                            "PASS",
                            "NONE",
                            "No public subnet route associations were detected.",
                            "No action required. Continue separating public and private workloads."
                    )
            );
        }

        System.out.println(
                "Public Subnets / Public Routes Found: "
                        + publicSubnetCount
        );

    } catch (Exception e) {

        System.out.println(
                "Public subnet scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-VPC-001",
                        "VPC Public Subnet Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not inspect VPC route tables.",
                        "Verify that CloudSentry has permission to describe EC2 route tables."
                )
        );
    }

    return findings;
}
// =========================================================
// VPC INTERNET GATEWAY CHECK
// =========================================================

private List<SecurityFinding> scanInternetGateways() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("----------------------------------------");
    System.out.println("       Internet Gateway Checks");
    System.out.println("----------------------------------------");

    try {

        DescribeInternetGatewaysResponse response =
                ec2Client.describeInternetGateways(
                        DescribeInternetGatewaysRequest.builder()
                                .build()
                );

        int attachedGatewayCount = 0;

        for (InternetGateway gateway :
                response.internetGateways()) {

            if (gateway.attachments().isEmpty()) {
                continue;
            }

            String gatewayId = gateway.internetGatewayId();

            for (var attachment :
                    gateway.attachments()) {

                if (!"available".equalsIgnoreCase(
                        attachment.stateAsString())) {
                    continue;
                }

                String vpcId = attachment.vpcId();

                if (vpcId == null) {
                    continue;
                }

                attachedGatewayCount++;

               System.out.println(
        "Internet Gateway: " + gatewayId
                + " | VPC: " + vpcId
                + " | ATTACHED [INFO]"
);

                findings.add(
                        new SecurityFinding(
                                "CS-VPC-002",
                                "VPC Internet Gateway - "
                                        + gatewayId,
                                "INFO",
                                "NONE",
                                "VPC " + vpcId
                                        + " has an attached Internet Gateway "
                                        + gatewayId
                                        + ", enabling internet connectivity.",
                                "Verify that only intended public subnets and resources use internet-facing routes through this gateway."
                        )
                );
            }
        }

        if (attachedGatewayCount == 0) {

            System.out.println(
                    "Attached Internet Gateways: NONE [PASS]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-VPC-002",
                            "VPC Internet Gateways",
                            "PASS",
                            "NONE",
                            "No active Internet Gateway attachments were detected.",
                            "No action required."
                    )
            );
        }

        System.out.println(
                "Active Internet Gateway Attachments: "
                        + attachedGatewayCount
        );

    } catch (Exception e) {

        System.out.println(
                "Internet Gateway scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-VPC-002",
                        "VPC Internet Gateway Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not inspect Internet Gateway attachments.",
                        "Verify that CloudSentry has permission to describe Internet Gateways."
                )
        );
    }

    return findings;
}

// =========================================================
// VPC DEFAULT SECURITY GROUP CHECK
// =========================================================

private List<SecurityFinding> scanDefaultSecurityGroups() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("----------------------------------------");
    System.out.println("       Default Security Group Checks");
    System.out.println("----------------------------------------");

    try {

        DescribeSecurityGroupsResponse response =
                ec2Client.describeSecurityGroups(
                        DescribeSecurityGroupsRequest.builder()
                                .filters(
                                        software.amazon.awssdk.services.ec2.model.Filter.builder()
                                                .name("group-name")
                                                .values("default")
                                                .build()
                                )
                                .build()
                );

        int riskyDefaultGroups = 0;

        for (var securityGroup : response.securityGroups()) {

            String groupId = securityGroup.groupId();
            String vpcId = securityGroup.vpcId();

            boolean publiclyAccessible = false;

            for (IpPermission permission :
                    securityGroup.ipPermissions()) {

                boolean publicIpv4 =
                        permission.ipRanges().stream()
                                .anyMatch(range ->
                                        "0.0.0.0/0".equals(
                                                range.cidrIp()
                                        ));

                boolean publicIpv6 =
                        permission.ipv6Ranges().stream()
                                .anyMatch(range ->
                                        "::/0".equals(
                                                range.cidrIpv6()
                                        ));

                if (publicIpv4 || publicIpv6) {
                    publiclyAccessible = true;
                    break;
                }
            }

            if (!publiclyAccessible) {
                continue;
            }

            riskyDefaultGroups++;

            System.out.println(
                    "Default Security Group: " + groupId
                            + " | VPC: " + vpcId
                            + " | PUBLIC INBOUND [HIGH]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-VPC-003",
                            "VPC Default Security Group - " + groupId,
                            "WARNING",
                            "HIGH",
                            "The default security group " + groupId
                                    + " allows inbound traffic from the public internet.",
                            "Remove public inbound rules from the default security group and use dedicated least-privilege security groups for workloads."
                    )
            );
        }

        if (riskyDefaultGroups == 0) {

            System.out.println(
                    "Public Default Security Groups: NONE [PASS]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-VPC-003",
                            "VPC Default Security Groups",
                            "PASS",
                            "NONE",
                            "No default security groups were detected with public inbound access.",
                            "No action required. Continue using dedicated least-privilege security groups."
                    )
            );
        }

        System.out.println(
                "Risky Default Security Groups Found: "
                        + riskyDefaultGroups
        );

    } catch (Exception e) {

        System.out.println(
                "Default security group scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-VPC-003",
                        "VPC Default Security Group Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not inspect default security group rules.",
                        "Verify that CloudSentry has permission to describe EC2 security groups."
                )
        );
    }

    return findings;
}

// =========================================================
// VPC NETWORK ACL EXPOSURE CHECK
// =========================================================

private List<SecurityFinding> scanNetworkAclExposure() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("----------------------------------------");
    System.out.println("       Network ACL Exposure Checks");
    System.out.println("----------------------------------------");

    try {

        DescribeNetworkAclsResponse response =
                ec2Client.describeNetworkAcls(
                        DescribeNetworkAclsRequest.builder()
                                .build()
                );

        int checkedAclCount = 0;
        int exposedAclCount = 0;

        for (var acl : response.networkAcls()) {

            String aclId = acl.networkAclId();

            if (aclId == null || aclId.isBlank()) {
                continue;
            }

            checkedAclCount++;

            boolean riskyInboundRule = false;

            String exposureType = "";
            String protocol = "";
            String portRange = "";
            int ruleNumber = -1;

            /*
             * NACL rules are evaluated in ascending rule-number
             * order. The first matching rule determines whether
             * traffic is allowed or denied.
             *
             * CloudSentry therefore looks specifically for
             * unrestricted inbound ALLOW rules.
             */

            for (var entry : acl.entries()) {

                /*
                 * Ignore outbound rules.
                 * CS-VPC-004 focuses on inbound exposure.
                 */
                if (entry.egress()) {
                    continue;
                }

                /*
                 * Ignore DENY rules.
                 *
                 * A DENY rule does not create internet exposure.
                 */
                if (!"allow".equalsIgnoreCase(
                        entry.ruleActionAsString())) {
                    continue;
                }

                boolean publicIpv4 =
                        "0.0.0.0/0".equals(entry.cidrBlock());

                boolean publicIpv6 =
                        "::/0".equals(entry.ipv6CidrBlock());

                if (!publicIpv4 && !publicIpv6) {
                    continue;
                }

                /*
                 * We found an unrestricted inbound ALLOW rule.
                 */
                riskyInboundRule = true;

                ruleNumber = entry.ruleNumber();

                protocol = entry.protocol();

                /*
                 * Describe the affected ports.
                 */
                Integer fromPort = entry.portRange() != null
                        ? entry.portRange().from()
                        : null;

                Integer toPort = entry.portRange() != null
                        ? entry.portRange().to()
                        : null;

                if (fromPort == null || toPort == null) {

                    portRange = "ALL PORTS";

                } else if (fromPort.equals(toPort)) {

                    portRange = String.valueOf(fromPort);

                } else {

                    portRange =
                            fromPort + "-" + toPort;
                }

                if (publicIpv4 && publicIpv6) {

                    exposureType = "IPv4 and IPv6";

                } else if (publicIpv4) {

                    exposureType = "IPv4";

                } else {

                    exposureType = "IPv6";
                }

                /*
                 * Stop after the first unrestricted inbound
                 * ALLOW rule because NACL rule ordering matters.
                 */
                break;
            }

            if (riskyInboundRule) {

                exposedAclCount++;

                System.out.println(
                        "Network ACL: " + aclId
                                + " | Rule: " + ruleNumber
                                + " | Protocol: " + protocol
                                + " | Ports: " + portRange
                                + " | Public: " + exposureType
                                + " [HIGH]"
                );

                findings.add(
                        new SecurityFinding(
                                "CS-VPC-004",
                                "VPC Network ACL Public Inbound Access - "
                                        + aclId
                                        + " - Rule "
                                        + ruleNumber,

                                "WARNING",

                                "HIGH",

                                "Network ACL "
                                        + aclId
                                        + " contains an unrestricted inbound ALLOW rule "
                                        + "(rule "
                                        + ruleNumber
                                        + ") allowing "
                                        + exposureType
                                        + " traffic on "
                                        + protocol
                                        + " ports "
                                        + portRange
                                        + " from the public internet.",

                                "Restrict inbound Network ACL rules to trusted CIDR ranges and required ports. Remove unnecessary 0.0.0.0/0 or ::/0 ALLOW rules and use least-privilege network access."
                        )
                );

            } else {

                System.out.println(
                        "Network ACL: " + aclId
                                + " | No unrestricted inbound "
                                + "ALLOW rule [PASS]"
                );

                findings.add(
                        new SecurityFinding(
                                "CS-VPC-004",
                                "VPC Network ACL Public Inbound Access - "
                                        + aclId,

                                "PASS",

                                "NONE",

                                "Network ACL "
                                        + aclId
                                        + " does not contain an unrestricted inbound ALLOW rule for public IPv4 or IPv6 traffic.",

                                "No action required. Continue restricting Network ACL rules to trusted networks and required traffic."
                        )
                );
            }
        }

        /*
         * No ACLs were returned.
         */
        if (checkedAclCount == 0) {

            System.out.println(
                    "Network ACLs: NONE [PASS]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-VPC-004",
                            "VPC Network ACL Public Inbound Access",
                            "PASS",
                            "NONE",
                            "No Network ACLs were found in the selected region.",
                            "No action required."
                    )
            );
        }

        System.out.println();
        System.out.println(
                "Network ACLs Checked: "
                        + checkedAclCount
        );

        System.out.println(
                "Network ACLs with Public Inbound Access: "
                        + exposedAclCount
        );

    } catch (Exception e) {

        System.out.println(
                "Network ACL scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-VPC-004",
                        "VPC Network ACL Public Inbound Access",
                        "ERROR",
                        "HIGH",
                        "Unable to determine Network ACL exposure: "
                                + e.getMessage(),
                        "Verify AWS permissions and retry the scan."
                )
        );
    }

    return findings;
}

// =========================================================
// VPC PUBLIC IPV6 ROUTE CHECK
// =========================================================

private List<SecurityFinding> scanPublicIpv6Routes() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("----------------------------------------");
    System.out.println("       Public IPv6 Route Checks");
    System.out.println("----------------------------------------");

    try {

        DescribeRouteTablesResponse response =
                ec2Client.describeRouteTables(
                        DescribeRouteTablesRequest.builder()
                                .build()
                );

        int publicIpv6RouteCount = 0;

        for (RouteTable routeTable : response.routeTables()) {

            String routeTableId =
                    routeTable.routeTableId();

            for (Route route : routeTable.routes()) {

                boolean publicIpv6Route =
                        "::/0".equals(
                                route.destinationIpv6CidrBlock()
                        );

                boolean internetGatewayRoute =
                        route.gatewayId() != null
                        && route.gatewayId().startsWith("igw-");

                boolean activeRoute =
                        "active".equalsIgnoreCase(
                                route.stateAsString()
                        );

                if (!publicIpv6Route
                        || !internetGatewayRoute
                        || !activeRoute) {
                    continue;
                }

                publicIpv6RouteCount++;

                System.out.println(
                        "Route Table: " + routeTableId
                                + " | Destination: ::/0"
                                + " | Gateway: "
                                + route.gatewayId()
                                + " | PUBLIC IPv6 [HIGH]"
                );

                findings.add(
                        new SecurityFinding(
                                "CS-VPC-006",
                                "VPC Public IPv6 Route - "
                                        + routeTableId,
                                "WARNING",
                                "HIGH",
                                "Route table " + routeTableId
                                        + " sends all IPv6 traffic (::/0) through Internet Gateway "
                                        + route.gatewayId()
                                        + ".",
                                "Use IPv6 Internet Gateway routes only for intentionally public subnets and keep sensitive workloads on private or egress-only IPv6 paths."
                        )
                );
            }
        }

        if (publicIpv6RouteCount == 0) {

            System.out.println(
                    "Public IPv6 Routes: NONE [PASS]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-VPC-006",
                            "VPC Public IPv6 Routes",
                            "PASS",
                            "NONE",
                            "No active IPv6 default routes (::/0) to an Internet Gateway were detected.",
                            "No action required. Continue restricting IPv6 internet exposure."
                    )
            );
        }

        System.out.println(
                "Public IPv6 Routes Found: "
                        + publicIpv6RouteCount
        );

    } catch (Exception e) {

        System.out.println(
                "Public IPv6 route scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-VPC-006",
                        "VPC Public IPv6 Route Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not inspect IPv6 route-table configuration.",
                        "Verify that CloudSentry has permission to describe VPC route tables."
                )
        );
    }

    return findings;
}
// =========================================================
// VPC FLOW LOGS CHECK
// =========================================================

private List<SecurityFinding> scanFlowLogs() {

    List<SecurityFinding> findings = new ArrayList<>();

    System.out.println();
    System.out.println("----------------------------------------");
    System.out.println("       VPC Flow Logs Checks");
    System.out.println("----------------------------------------");

    try {

        /*
         * Get all VPCs in the selected region.
         */
        DescribeVpcsResponse vpcResponse =
                ec2Client.describeVpcs(
                        DescribeVpcsRequest.builder()
                                .build()
                );

        /*
         * Get all VPC Flow Logs in one API call.
         *
         * This is intentionally done once instead of
         * calling DescribeFlowLogs separately for every VPC.
         */
        DescribeFlowLogsResponse flowLogsResponse =
                ec2Client.describeFlowLogs(
                        DescribeFlowLogsRequest.builder()
                                .build()
                );

        int checkedVpcCount = 0;
        int activeFlowLogVpcCount = 0;

        for (var vpc : vpcResponse.vpcs()) {

            String vpcId = vpc.vpcId();

            if (vpcId == null || vpcId.isBlank()) {
                continue;
            }

            checkedVpcCount++;

            boolean activeFlowLogFound = false;

            /*
             * Check whether this VPC has an active Flow Log.
             */
            for (var flowLog : flowLogsResponse.flowLogs()) {

                /*
                 * Only consider Flow Logs associated with
                 * this VPC.
                 */
                if (!vpcId.equals(flowLog.resourceId())) {
                    continue;
                }

                /*
                 * Flow Log status must be ACTIVE.
                 */
                if ("ACTIVE".equalsIgnoreCase(
                    flowLog.flowLogStatus())) {

                    activeFlowLogFound = true;
                    break;
                }
            }

            if (activeFlowLogFound) {

                activeFlowLogVpcCount++;

                System.out.println(
                        "VPC: " + vpcId
                                + " | Flow Logs: ACTIVE [PASS]"
                );

                findings.add(
                        new SecurityFinding(
                                "CS-VPC-005",
                                "VPC Flow Logs - " + vpcId,
                                "PASS",
                                "NONE",
                                "An active VPC Flow Log configuration was detected for VPC "
                                        + vpcId
                                        + ".",
                                "No action required. Continue monitoring network traffic for this VPC."
                        )
                );

            } else {

                System.out.println(
                        "VPC: " + vpcId
                                + " | Flow Logs: NOT ACTIVE [MEDIUM]"
                );

                findings.add(
                        new SecurityFinding(
                                "CS-VPC-005",
                                "VPC Flow Logs - " + vpcId,
                                "WARNING",
                                "MEDIUM",
                                "No active VPC Flow Log configuration was detected for VPC "
                                        + vpcId
                                        + ".",
                                "Enable VPC Flow Logs for this VPC to improve network visibility, investigation, and security monitoring."
                        )
                );
            }
        }

        /*
         * Summary information.
         */
        System.out.println();

        System.out.println(
                "VPCs Checked: "
                        + checkedVpcCount
        );

        System.out.println(
                "VPCs with Active Flow Logs: "
                        + activeFlowLogVpcCount
        );

    } catch (Exception e) {

        System.out.println(
                "VPC Flow Logs scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-VPC-005",
                        "VPC Flow Logs Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not determine whether VPC Flow Logs are active.",
                        "Verify AWS permissions and VPC Flow Logs availability, then retry the scan."
                )
        );
    }

    return findings;
}
}