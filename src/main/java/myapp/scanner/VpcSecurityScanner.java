package myapp.scanner;

import myapp.config.AwsClientFactory;
import myapp.model.SecurityFinding;
import org.springframework.stereotype.Component;

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

   private final AwsClientFactory awsClientFactory;
private Ec2Client ec2Client;

public VpcSecurityScanner(AwsClientFactory awsClientFactory) {
    this.awsClientFactory = awsClientFactory;
}


    @Override
public List<SecurityFinding> scan(String region) {

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

            DescribeRouteTablesResponse response =
                    ec2Client.describeRouteTables(
                            DescribeRouteTablesRequest.builder()
                                    .build()
                    );

            int publicSubnetCount = 0;

            for (RouteTable routeTable : response.routeTables()) {

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

                if (routeTable.associations().isEmpty()) {

                    System.out.println(
                            "Route Table: " + routeTableId
                                    + " | Public Route Detected [MEDIUM]"
                    );

                    findings.add(
                            new SecurityFinding(
                                    "CS-VPC-001",
                                    "VPC Public Route Table - "
                                            + routeTableId,
                                    "WARNING",
                                    "MEDIUM",
                                    "Route table " + routeTableId
                                            + " contains an active IPv4 default route to an Internet Gateway.",
                                    "Ensure only intended public subnets use this route table and keep sensitive workloads in private subnets."
                            )
                    );

                    publicSubnetCount++;
                    continue;
                }

                for (var association :
                        routeTable.associations()) {

                    if (association.subnetId() == null) {
                        continue;
                    }

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
                                            + " uses a route table with an active default route to an Internet Gateway.",
                                    "Keep sensitive workloads in private subnets and expose only resources that require direct internet connectivity."
                            )
                    );

                    publicSubnetCount++;
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
                                "No explicitly associated subnets with an active default IPv4 route to an Internet Gateway were detected.",
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
                                + " | ATTACHED [LOW]"
                );

                findings.add(
                        new SecurityFinding(
                                "CS-VPC-002",
                                "VPC Internet Gateway - "
                                        + gatewayId,
                                "INFO",
                                "LOW",
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

        int riskyAclCount = 0;

        for (NetworkAcl networkAcl : response.networkAcls()) {

            String networkAclId = networkAcl.networkAclId();
            boolean riskyInboundRule = false;

            for (var entry : networkAcl.entries()) {

                if (entry.egress()) {
                    continue;
                }

                boolean publicIpv4 =
                        "0.0.0.0/0".equals(entry.cidrBlock());

                boolean allowRule =
                        !entry.ruleActionAsString()
                                .equalsIgnoreCase("deny");

                if (publicIpv4 && allowRule) {
                    riskyInboundRule = true;
                    break;
                }
            }

            if (!riskyInboundRule) {
                continue;
            }

            riskyAclCount++;

            System.out.println(
                    "Network ACL: " + networkAclId
                            + " | Public IPv4 ALLOW [HIGH]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-VPC-004",
                            "VPC Public Network ACL - " + networkAclId,
                            "WARNING",
                            "HIGH",
                            "Network ACL " + networkAclId
                                    + " allows inbound IPv4 traffic from 0.0.0.0/0.",
                            "Restrict inbound Network ACL rules to trusted CIDR ranges and deny unnecessary internet access."
                    )
            );
        }

        if (riskyAclCount == 0) {

            System.out.println(
                    "Public Network ACL Rules: NONE [PASS]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-VPC-004",
                            "VPC Public Network ACL Rules",
                            "PASS",
                            "NONE",
                            "No allowing Network ACL entries were detected for unrestricted IPv4 inbound traffic from 0.0.0.0/0.",
                            "No action required. Continue using restrictive Network ACL rules."
                    )
            );
        }

        System.out.println(
                "Network ACLs with Public Inbound Access: "
                        + riskyAclCount
        );

    } catch (Exception e) {

        System.out.println(
                "Network ACL scan failed: "
                        + e.getMessage()
        );

        findings.add(
                new SecurityFinding(
                        "CS-VPC-004",
                        "VPC Network ACL Scan",
                        "ERROR",
                        "HIGH",
                        "CloudSentry could not inspect VPC Network ACL rules.",
                        "Verify that CloudSentry has permission to describe Network ACLs."
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

        DescribeFlowLogsResponse response =
                ec2Client.describeFlowLogs(
                        DescribeFlowLogsRequest.builder()
                                .build()
                );

        boolean activeFlowLogs = response.flowLogs()
                .stream()
                .anyMatch(flowLog ->
                        "ACTIVE".equalsIgnoreCase(
                                flowLog.flowLogStatus()
                        )
                );

        if (activeFlowLogs) {

            System.out.println(
                    "VPC Flow Logs: ACTIVE [PASS]"
            );

            findings.add(
                    new SecurityFinding(
                            "CS-VPC-005",
                            "VPC Flow Logs",
                            "PASS",
                            "NONE",
                            "At least one active VPC Flow Log configuration was detected.",
                            "No action required. Continue monitoring network traffic."
                    )
            );

        } else {

            System.out.println(
                    "VPC Flow Logs: NOT ACTIVE [MEDIUM]"
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
        }

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
                        "CloudSentry could not inspect VPC Flow Logs.",
                        "Verify that CloudSentry has permission to describe VPC Flow Logs."
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
}