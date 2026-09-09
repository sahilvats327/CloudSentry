# CloudSentry

CloudSentry is an AWS cloud security scanning CLI built with **Java, Spring Boot, AWS SDK for Java, and Picocli**.

It analyzes AWS cloud configurations across **IAM, S3, EC2, VPC, and Cost** to identify potential security and configuration risks.

CloudSentry generates security findings with **severity levels, recommendations, risk scoring, and security reports**. It also provides an **offline/mock scanning mode** for development, testing, and demonstrations without requiring access to a live AWS environment.

---

## Features

* AWS security scanning using AWS SDK for Java
* Offline/mock scanning mode for development and demonstration
* IAM security analysis
* S3 security analysis
* EC2 security analysis
* VPC security analysis
* Cost and cloud resource risk analysis
* HIGH, MEDIUM, and LOW severity classification
* Overall security score
* Overall risk level
* Security finding recommendations
* Severity-based filtering
* JSON security report generation
* HTML security report generation
* CLI exit codes for security automation
* Spring Boot based architecture
* Picocli command-line interface
* Modular scanner architecture
* Automated unit testing for risk evaluation

---

# Security Coverage

## IAM Security

CloudSentry analyzes IAM configurations for common identity and access-management risks.

Current checks include:

* Root account MFA
* Root access keys
* User MFA
* Access key age
* Access key usage
* Inline IAM policies
* Managed IAM policies
* Group policies
* Password policy
* AdministratorAccess
* Multiple active access keys
* Inactive access keys
* Privilege escalation actions

These checks help identify excessive privileges, weak authentication configurations, and potentially risky IAM access patterns.

---

## S3 Security

CloudSentry analyzes Amazon S3 bucket security configurations.

Current checks include:

* Public access block configuration
* Bucket encryption
* Bucket versioning
* Bucket logging
* HTTPS-only access
* Public bucket policies
* Cross-account access
* Object ownership
* Public write/delete access

These checks help identify publicly exposed buckets, missing encryption, insecure policies, and other common S3 configuration risks.

---

## EC2 Security

CloudSentry analyzes Amazon EC2 instances, security groups, EBS volumes, snapshots, and AMIs.

Current checks include:

* Public security group access
* EBS volume encryption
* Public IP exposure
* IMDSv2 enforcement
* Termination protection
* Public EBS snapshots
* EBS snapshot encryption
* Sensitive port exposure
* Unrestricted outbound traffic
* Public IPv6 security-group access
* Public AMI exposure
* Unencrypted EBS volumes

These checks help identify publicly exposed infrastructure and insecure compute and storage configurations.

---

## VPC Security

CloudSentry analyzes Amazon VPC networking configurations.

Current checks include:

* Public subnet exposure
* Internet Gateway detection
* Default security group exposure
* Network ACL exposure
* VPC Flow Logs
* Public IPv6 routes

These checks help identify potentially exposed network resources and missing network-level security controls.

---

## Cost Security

CloudSentry also performs cloud cost-related security and configuration analysis.

The cost scanner is designed to identify potentially risky or unnecessary cloud-resource configurations that may contribute to unexpected AWS costs.

Cost analysis is integrated into the same scanning and risk-evaluation architecture as the security scanners.

CloudSentry also provides a **Mock Cost Scanner** for demonstrations and offline testing.

---

# Risk Engine

CloudSentry uses a centralized **Risk Engine** to evaluate security findings.

Each finding is classified according to its severity:

* **HIGH** — Critical or potentially dangerous configuration
* **MEDIUM** — Significant security or configuration weakness
* **LOW** — Lower-risk issue or recommended improvement

The Risk Engine combines security findings into an overall security assessment.

The final report includes:

* Total findings
* HIGH findings
* MEDIUM findings
* LOW findings
* Overall security score
* Overall risk level
* Individual recommendations

This allows users to quickly understand the overall security posture of the scanned environment.

---

# Scan Modes

CloudSentry supports two primary scanning approaches.

## Mock / Offline Mode

Mock mode allows CloudSentry to run without connecting to a live AWS environment.

This is useful for:

* Development
* Testing
* College demonstrations
* Project presentations
* CI/testing environments
* Demonstrating security findings without AWS credentials

Example:

```bash
mvn spring-boot:run -Dspring-boot.run.arguments="scan --mock"
```

Mock scanners simulate AWS security findings for the supported services.

---

## AWS Scan Mode

CloudSentry can also use the **AWS SDK for Java** to inspect real AWS resources.

The AWS scanning architecture uses AWS services and APIs to retrieve configuration information and evaluate it against security checks.

AWS credentials and permissions must be configured correctly before running a live scan.

---

# Architecture

```text
                         CloudSentry CLI
                               |
                         Picocli Command
                               |
                         Spring Boot
                               |
                          ScanService
                               |
          +--------------------+--------------------+
          |          |          |          |        |
         IAM         S3        EC2        VPC      COST
          |          |          |          |        |
          +----------+----------+----------+--------+
                               |
                        Security Findings
                               |
                          Risk Engine
                               |
                    +----------+----------+
                    |                     |
              Console Report         ReportService
                                          |
                                +---------+---------+
                                |                   |
                           JSON Report         HTML Report
```

---

# Project Structure

```text
CloudSentry/
│
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── myapp/
│   │   │       ├── ScanCommand.java
│   │   │       │
│   │   │       ├── config/
│   │   │       │   └── AwsClientFactory.java
│   │   │       │
│   │   │       ├── model/
│   │   │       │   ├── ScanSummary.java
│   │   │       │   ├── SecurityFinding.java
│   │   │       │   └── SecurityReport.java
│   │   │       │
│   │   │       ├── scanner/
│   │   │       │   ├── IamSecurityScanner.java
│   │   │       │   ├── MockIamSecurityScanner.java
│   │   │       │   ├── S3SecurityScanner.java
│   │   │       │   ├── Ec2SecurityScanner.java
│   │   │       │   ├── MockEc2SecurityScanner.java
│   │   │       │   ├── VpcSecurityScanner.java
│   │   │       │   ├── MockVpcSecurityScanner.java
│   │   │       │   ├── CostSecurityScanner.java
│   │   │       │   └── MockCostSecurityScanner.java
│   │   │       │
│   │   │       ├── service/
│   │   │       │   ├── ScanService.java
│   │   │       │   ├── RiskEngine.java
│   │   │       │   └── ReportService.java
│   │   │       │
│   │   │       └── ...
│   │   │
│   │   └── resources/
│   │       ├── application.properties
│   │       └── templates/
│   │           └── security-report.html
│   │
│   └── test/
│       └── java/
│           └── myapp/
│               └── service/
│                   └── RiskEngineTest.java
│
├── pom.xml
└── README.md
```

---

# Technologies Used

| Technology       | Purpose                               |
| ---------------- | ------------------------------------- |
| Java             | Core application development          |
| Spring Boot      | Application framework                 |
| AWS SDK for Java | AWS resource and configuration access |
| Picocli          | Command-line interface                |
| Maven            | Build and dependency management       |
| JUnit            | Unit testing                          |
| HTML/CSS         | Security report presentation          |
| JSON             | Security report data format           |

---

# AWS Services

CloudSentry is designed to interact with AWS services and configurations including:

* **AWS Identity and Access Management (IAM)**
* **Amazon S3**
* **Amazon EC2**
* **Amazon VPC**
* AWS networking and security configurations
* AWS cost/resource information

The exact AWS permissions required depend on the scanners and checks being executed.

---

# Requirements

Before running CloudSentry in live AWS mode, make sure you have:

* Java JDK installed
* Maven installed
* AWS CLI installed
* AWS credentials configured
* Appropriate AWS IAM permissions
* An AWS region configured

For development and demonstrations, AWS credentials are **not required when using mock mode**.

---

# Build the Project

Clone the repository and move into the project directory:

```bash
git clone https://github.com/sahilvats327/CloudSentry.git
cd CloudSentry
```

Build the project using Maven:

```bash
mvn clean compile
```

---

# Run CloudSentry

## Mock Scan

Run an offline security scan using simulated AWS data:

```bash
mvn spring-boot:run -Dspring-boot.run.arguments="scan --mock"
```

This mode allows the complete scanning pipeline to be demonstrated without accessing AWS.

---

## Run Tests

Run the automated tests using:

```bash
mvn test
```

The project includes unit tests for components such as the Risk Engine.

---

# Security Reports

CloudSentry produces structured security results that can be used for analysis and reporting.

## JSON Report

The JSON report provides machine-readable scan results.

Example structure:

```json
{
  "securityScore": 75,
  "riskLevel": "MEDIUM",
  "high": 2,
  "medium": 4,
  "low": 3
}
```

The JSON format makes the results suitable for:

* Automation
* Further analysis
* CI/CD integrations
* Security dashboards
* External tools

---

## HTML Report

CloudSentry also provides an HTML-based security report.

The report presents the scan results in a human-readable format, including:

* Executive summary
* Security score
* Risk level
* Severity distribution
* Security findings
* Recommendations
* Scan information

This makes the results easier to understand during security reviews and project demonstrations.

---

# Example Scan Flow

```text
User
 |
 |  scan --mock
 v
ScanCommand
 |
 v
ScanService
 |
 +---- IAM Scanner
 |
 +---- S3 Scanner
 |
 +---- EC2 Scanner
 |
 +---- VPC Scanner
 |
 +---- Cost Scanner
 |
 v
Security Findings
 |
 v
Risk Engine
 |
 v
Security Score
 |
 +-------------------+
 |                   |
 v                   v
Console Output    ReportService
                       |
                +------+------+
                |             |
                v             v
             JSON           HTML
             Report         Report
```

---

# Security Finding Model

Each security finding contains information used to explain and prioritize a potential risk.

Typical finding information includes:

* Resource
* Service
* Finding title
* Description
* Severity
* Recommendation
* Security impact

This structure allows CloudSentry to maintain consistent findings across different AWS services.

---

# Automation

CloudSentry is designed as a CLI application so that security scanning can be integrated into automated workflows.

CLI exit codes can be used by automation systems to determine whether security issues were detected.

Potential future integrations include:

* CI/CD pipelines
* GitHub Actions
* Jenkins
* Scheduled security scans
* Cloud security dashboards
* Automated compliance checks

---

# Development Approach

CloudSentry follows a modular scanner architecture.

Each AWS service has its own scanner responsible for performing service-specific security checks.

```text
Scanner
   |
   +---- IAM
   +---- S3
   +---- EC2
   +---- VPC
   +---- COST
```

Mock scanners provide equivalent offline implementations for development and demonstrations.

This architecture makes it easier to:

* Add new AWS services
* Add new security checks
* Test scanners independently
* Run scans without AWS access
* Extend the project for future automation

---

# Future Improvements

Potential future improvements include:

* Additional AWS service scanners
* AWS Config integration
* CloudTrail security analysis
* CloudWatch security monitoring
* Automated remediation
* Compliance frameworks
* CIS benchmark mapping
* Continuous security monitoring
* CI/CD integration
* GitHub Actions integration
* Email security alerts
* Improved cost anomaly detection
* More advanced risk scoring
* Interactive security dashboards
* Historical scan comparison
* Multi-region scanning

---

# Disclaimer

CloudSentry is an educational and security-auditing project designed to help identify potentially insecure AWS configurations.

It should not be considered a replacement for a professional cloud security platform or a complete AWS security audit.

Always review findings before making changes to production infrastructure.

---

# Project Status

**Current status: Active Development**

CloudSentry currently supports security analysis across:

```text
IAM
S3
EC2
VPC
COST
```

with both **AWS scanning** and **offline/mock scanning** capabilities.

---

# Author

**Sahil Vats**

CloudSentry was developed as a cloud security project using Java, Spring Boot, AWS SDK for Java, and Picocli.
