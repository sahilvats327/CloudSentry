
package myapp;

import myapp.service.ScanService;
import org.springframework.stereotype.Component;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.concurrent.Callable;

@Component
@Command(
        name = "scan",
        description = "Run a CloudSentry security scan",
        mixinStandardHelpOptions = true
)
public class ScanCommand implements Callable<Integer> {

    private final ScanService scanService;

    public ScanCommand(ScanService scanService) {
        this.scanService = scanService;
    }

    @Option(
            names = "--security",
            description = "Enable security checks"
    )
    private boolean security;

    @Option(
            names = "--output",
            description = "JSON report output filename",
            defaultValue = "cloudsentry-report.json"
    )
    private String output;

    @Option(
            names = "--s3",
            description = "Run only S3 security checks"
    )
    private boolean s3;

    @Option(
            names = "--iam",
            description = "Run only IAM security checks"
    )
    private boolean iam;

    @Option(
            names = "--ec2",
            description = "Run only EC2 security checks"
    )
    private boolean ec2;

    @Option(
    names = "--vpc",
    description = "Run VPC security checks"
)
private boolean vpc;

    @Option(
        names = "--region",
        description = "AWS region to scan (example: ap-south-1)",
        defaultValue = "ap-south-1"
)
    private String region;
    
    @Option(
            names = "--mock",
            description = "Run the security scan using simulated AWS data"
)
private boolean mock;

@Option(
        names = "--severity",
        description = "Filter findings by severity: HIGH, MEDIUM, LOW, or ALL",
        defaultValue = "ALL"
)
private String severity;

@Option(
        names = "--cost",
        description = "Run only Cost optimization checks"
)
private boolean cost;
    
    @Override
public Integer call() {

    boolean targetedScan = s3 || iam || ec2 || vpc || cost;

    if (targetedScan && !security) {

        System.out.println();
        System.out.println("Invalid scan configuration.");
        System.out.println(
        "Use --security when specifying --s3, --iam, --ec2, --vpc, or --cost."
);

        return 4;
    }
if (!severity.equalsIgnoreCase("ALL")
        && !severity.equalsIgnoreCase("HIGH")
        && !severity.equalsIgnoreCase("MEDIUM")
        && !severity.equalsIgnoreCase("LOW")) {

    System.out.println();
    System.out.println("Invalid severity value.");
    System.out.println(
            "Use HIGH, MEDIUM, LOW, or ALL."
    );

    return 5;
}
    System.out.println();
System.out.println("----------------------------------------");
System.out.println("Scan Configuration");
System.out.println("----------------------------------------");
System.out.println(
        "Mode:       " + (mock ? "MOCK / OFFLINE" : "AWS")
);
System.out.println(
        "Region:     " + region
);

if (s3 || iam || ec2 || vpc || cost) {

    StringBuilder targets = new StringBuilder();

    if (s3) {
        targets.append("S3");
    }

    if (iam) {
        if (targets.length() > 0) {
            targets.append(", ");
        }
        targets.append("IAM");
    }

    if (ec2) {
        if (targets.length() > 0) {
            targets.append(", ");
        }
        targets.append("EC2");
    }
  if (vpc) {
    if (targets.length() > 0) {
        targets.append(", ");
    }
    targets.append("VPC");
}

if (cost) {
    if (targets.length() > 0) {
        targets.append(", ");
    }
    targets.append("COST");
}

    System.out.println(
            "Targets:    " + targets
    );

} else {

    System.out.println(
            "Targets:    S3, IAM, EC2, VPC, COST"
    );
}

System.out.println("----------------------------------------");

    return scanService.scan(
        security,
        output,
        s3,
        iam,
        ec2,
        vpc,
        cost,
        region,
        mock,
        severity
);
}
}

