# CloudSentry

**CloudSentry** is an AWS cloud security and reliability scanning CLI built with **Java, Spring Boot, AWS SDK for Java, and Picocli**.

It analyzes AWS configurations across **IAM, S3, EC2, VPC, Cost, and Reliability** to identify potential security, configuration, availability, and resilience risks.

CloudSentry converts detected issues into structured **security findings**, assigns severity levels, calculates an overall **security score and risk level**, and generates **JSON and HTML security reports**.

The project also provides an **offline/mock scanning mode**, allowing the complete scanning and reporting workflow to be demonstrated without requiring access to a live AWS environment.

---

# 🚀 Features

* AWS security scanning using AWS SDK for Java
* Offline/mock scanning mode
* IAM security analysis
* S3 security analysis
* EC2 security analysis
* VPC security analysis
* Cloud cost/resource risk analysis
* Reliability and availability analysis
* RDS Multi-AZ checks
* S3 lifecycle checks
* EC2 Auto Scaling checks
* HIGH, MEDIUM, and LOW severity classification
* Centralized risk evaluation
* Overall security score
* Overall risk level
* Security recommendations
* Severity-based filtering
* JSON security reports
* HTML security reports
* CLI-based scanning
* CLI exit codes for automation
* Spring Boot architecture
* Picocli command-line interface
* Modular scanner architecture
* Mock scanner implementations
* Automated unit testing

---

# 🔐 Security Coverage

## IAM Security

CloudSentry analyzes IAM configurations for common identity and access-management risks.

Current IAM checks include:

* Root account MFA
* Root account access keys
* User MFA
* Access key age
* Access key usage
* Inline IAM policies
* Attached IAM policies
* Group policies
* Password policy
* Administrator-level permissions
* Multiple active access keys
* Inactive access keys
* Potentially dangerous IAM actions

These checks help identify weak authentication configurations, excessive permissions, and potentially risky access patterns.

---

## 🪣 S3 Security

CloudSentry analyzes Amazon S3 bucket configurations for common security risks.

Current S3 security checks include:

* Public access block configuration
* Bucket encryption
* Bucket versioning
* Bucket logging
* HTTPS-only access
* Public bucket policies
* Cross-account access
* Object ownership
* Public write/delete access

These checks help identify potentially exposed buckets, missing security controls, and insecure access configurations.

---

## 💻 EC2 Security

CloudSentry analyzes EC2 infrastructure and related security configurations.

Current EC2 security checks include:

* Public security group access
* Sensitive port exposure
* Public IP exposure
* EBS volume encryption
* IMDSv2 configuration
* Termination protection
* Public EBS snapshots
* Snapshot encryption
* Unrestricted outbound traffic
* Public IPv6 security-group access
* Public AMI exposure
* Unencrypted EBS volumes

These checks help identify publicly exposed compute resources and insecure storage or network configurations.

---

## 🌐 VPC Security

CloudSentry analyzes VPC networking configurations for potentially exposed resources.

Current VPC checks include:

* Public subnet exposure
* Internet Gateway detection
* Default security group exposure
* Network ACL configuration
* VPC Flow Logs
* Public IPv6 routes

These checks provide visibility into common network-level security risks.

---

# 🔄 Reliability & Availability

CloudSentry includes a dedicated **ReliabilitySecurityScanner** that analyzes AWS configurations related to availability, resilience, and workload recovery.

The reliability scanner currently performs three checks.

---

## RDS Multi-AZ — `CS-REL-001`

Checks whether Amazon RDS database instances have **Multi-AZ deployment** enabled.

A database without Multi-AZ may have reduced availability during an Availability Zone failure.

### Findings

* **MEDIUM** — Multi-AZ is disabled
* **PASS** — Multi-AZ is enabled
* **HIGH** — CloudSentry cannot determine the configuration because of a scanning error

### Recommendation

Enable Multi-AZ for production RDS workloads that require high availability.

---

## S3 Lifecycle — `CS-REL-002`

Checks whether S3 buckets have a **lifecycle configuration**.

Lifecycle policies can help manage object retention, transition objects between storage classes, and automatically expire objects according to workload requirements.

### Findings

* **MEDIUM** — No lifecycle policy detected
* **PASS** — Lifecycle configuration exists
* **HIGH** — CloudSentry cannot determine the lifecycle configuration because of a scanning error

### Recommendation

Configure an appropriate S3 lifecycle policy based on the workload's retention and storage requirements.

---

## EC2 Auto Scaling — `CS-REL-003`

Checks whether EC2 instances are members of an **Auto Scaling Group**.

Instances that are not managed by Auto Scaling may not automatically recover or scale when required.

### Findings

* **MEDIUM** — EC2 instance is not in an Auto Scaling Group
* **PASS** — EC2 instance belongs to an Auto Scaling Group
* **HIGH** — CloudSentry cannot determine Auto Scaling membership because of a scanning error

### Recommendation

For workloads requiring high availability and automatic recovery, consider placing EC2 instances in an appropriate Auto Scaling Group.

---

## Reliability Scanner Architecture

```text
                ReliabilitySecurityScanner
                           |
             +-------------+-------------+
             |             |             |
             v             v             v
            RDS           S3            EC2
          Multi-AZ     Lifecycle     Auto Scaling
             |             |             |
             +-------------+-------------+
                           |
                    SecurityFinding
                           |
                       Risk Engine
```

The reliability scanner uses the same `SecurityFinding` model as the other CloudSentry scanners, allowing reliability findings to participate in the same reporting and risk-evaluation pipeline.

---

# 💰 Cost Security

CloudSentry also includes cloud cost and resource-risk analysis.

The cost scanner is designed to identify potentially unnecessary or risky cloud-resource configurations that may contribute to unexpected AWS costs.

Cost analysis is integrated into the same scanning and risk-evaluation architecture as the other scanners.

CloudSentry also provides a **Mock Cost Scanner** for demonstrations and offline testing.

---

# 📊 Risk Engine

CloudSentry uses a centralized **Risk Engine** to evaluate security findings.

Each finding is assigned a severity level:

| Severity   | Meaning                                         |
| ---------- | ----------------------------------------------- |
| **HIGH**   | Critical or potentially dangerous configuration |
| **MEDIUM** | Significant security or configuration weakness  |
| **LOW**    | Lower-risk issue or recommended improvement     |
| **PASS**   | Configuration passed the relevant check         |

The Risk Engine aggregates findings and produces an overall security assessment.

The final assessment includes:

* Total findings
* HIGH findings
* MEDIUM findings
* LOW findings
* Overall security score
* Overall risk level
* Individual recommendations

This provides a consolidated view of the scanned environment's security and configuration posture.

---

# 🧪 Scan Modes

CloudSentry supports two primary scanning approaches:

1. **Mock / Offline Scanning**
2. **AWS Scanning**

---

## Mock / Offline Mode

Mock mode allows CloudSentry to execute the scanning pipeline without connecting to a live AWS environment.

This is useful for:

* Development
* Testing
* College demonstrations
* Project presentations
* CI/testing environments
* Demonstrating security findings without AWS credentials

### Run a mock scan

```bash
mvn spring-boot:run -Dspring-boot.run.arguments="scan --mock"
```

### Run a security-focused mock scan

```bash
mvn spring-boot:run -Dspring-boot.run.arguments="scan --security --mock"
```

Mock scanners generate simulated findings for supported scanning areas.

This allows the complete pipeline to be demonstrated:

```text
Scan
  ↓
Scanner Execution
  ↓
Security Findings
  ↓
Risk Engine
  ↓
Security Score
  ↓
Reports
```

---

# ☁️ AWS Scan Mode

CloudSentry can use the **AWS SDK for Java** to inspect real AWS resources.

The AWS scanning architecture retrieves configuration information from AWS services and evaluates the configuration against CloudSentry checks.

Before running a live scan, ensure that:

* AWS credentials are configured
* The AWS account is active
* Required IAM permissions are available
* An AWS region is configured

> **Security:** Never commit AWS access keys, secret keys, passwords, or other credentials to the repository.

---

# 🏗️ Architecture

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
                       Reliability Scanner
                               |
                     +---------+---------+
                     |         |         |
                    RDS       S3        EC2
                  Multi-AZ  Lifecycle  Auto Scaling
                               |
                               v
                      Security Findings
                               |
                          Risk Engine
                               |
                  +------------+------------+
                  |                         |
            Console Output            ReportService
                                            |
                                  +---------+---------+
                                  |                   |
                              JSON Report        HTML Report
```

CloudSentry separates service-specific scanning logic from the central scanning, risk-evaluation, and reporting components.

This modular structure allows additional scanners and security checks to be added without redesigning the complete application.

---

# 📁 Project Structure

```text
CloudSentry/
│
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── myapp/
│   │   │
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
│   │   │       │   ├── MockCostSecurityScanner.java
│   │   │       │   └── ReliabilitySecurityScanner.java
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

# 🛠️ Technologies Used

| Technology           | Purpose                               |
| -------------------- | ------------------------------------- |
| **Java**             | Core application development          |
| **Spring Boot**      | Application framework                 |
| **AWS SDK for Java** | AWS resource and configuration access |
| **Picocli**          | Command-line interface                |
| **Maven**            | Build and dependency management       |
| **JUnit**            | Automated testing                     |
| **HTML/CSS**         | Security report presentation          |
| **JSON**             | Machine-readable security reports     |

---

# ☁️ AWS Services

CloudSentry currently analyzes configurations associated with:

* **AWS IAM**
* **Amazon S3**
* **Amazon EC2**
* **Amazon VPC**
* **Amazon RDS**
* **Amazon EC2 Auto Scaling**
* AWS networking and security configurations
* AWS cloud resource and cost information

The exact AWS permissions required depend on the scanner and checks being executed.

---

# ⚙️ Requirements

## Development

* Java JDK
* Maven
* Git

## Live AWS scanning

* AWS CLI
* Configured AWS credentials
* Appropriate IAM permissions
* Configured AWS region
* Active AWS account

AWS credentials are **not required for mock/offline mode**.

---

# 📦 Build the Project

Clone the repository:

```bash
git clone https://github.com/sahilvats327/CloudSentry.git
cd CloudSentry
```

Build the project:

```bash
mvn clean compile
```

---

# ▶️ Running CloudSentry

## Mock Scan

Run the offline scanner:

```bash
mvn spring-boot:run -Dspring-boot.run.arguments="scan --mock"
```

For a security-focused mock scan:

```bash
mvn spring-boot:run -Dspring-boot.run.arguments="scan --security --mock"
```

Mock mode allows the scanning, risk evaluation, and reporting pipeline to be tested without requiring a live AWS environment.

---

## AWS Scan

For live AWS scanning, configure valid AWS credentials and required permissions.

Then execute the appropriate CloudSentry scan command.

> Live AWS scanning may require additional permissions depending on the services and checks being analyzed.

---

# 🧪 Running Tests

Run the automated test suite:

```bash
mvn test
```

The project includes unit testing for components such as the **Risk Engine** and risk evaluation logic.

---

# 📄 Security Reports

CloudSentry produces structured security results through both machine-readable and human-readable reports.

## JSON Report

The JSON report contains structured scan information.

Example:

```json
{
  "securityScore": 75,
  "riskLevel": "MEDIUM",
  "high": 2,
  "medium": 4,
  "low": 3
}
```

JSON reports can be useful for:

* Automation
* Security analysis
* CI/CD integrations
* Dashboards
* External tools

---

## HTML Report

CloudSentry also generates an HTML-based security report.

The report provides a human-readable view of the scan, including:

* Executive summary
* Security score
* Risk level
* Severity distribution
* Security findings
* Recommendations
* Scan information

The HTML report is useful for:

* Security reviews
* Project demonstrations
* Presentations
* Manual analysis
* Sharing scan results

---

# 🔄 Example Scan Flow

```text
User
 |
 |  scan --security --mock
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
 +---- Reliability Scanner
          |
          +---- RDS Multi-AZ
          +---- S3 Lifecycle
          +---- EC2 Auto Scaling
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

# 🔎 Security Finding Model

Each CloudSentry finding contains structured information used to explain and prioritize a potential risk.

Typical finding information includes:

* Finding ID
* Resource
* AWS service
* Finding title
* Description
* Severity
* Recommendation
* Security impact

Examples of reliability finding IDs include:

```text
CS-REL-001  → RDS Multi-AZ
CS-REL-002  → S3 Lifecycle
CS-REL-003  → EC2 Auto Scaling
```

Using a common `SecurityFinding` model allows different scanners to produce consistent results.

---

# 🤖 Automation

CloudSentry is designed as a CLI application, making it suitable for automated security workflows.

CLI exit codes can be used by automation systems to determine whether security issues were detected.

Potential integrations include:

* CI/CD pipelines
* GitHub Actions
* Jenkins
* Scheduled scans
* Security dashboards
* Automated compliance checks

---

# 🧩 Development Approach

CloudSentry follows a **modular scanner architecture**.

Each scanning area has dedicated logic responsible for service-specific analysis.

```text
CloudSentry
    |
    +---- IAM
    |
    +---- S3
    |
    +---- EC2
    |
    +---- VPC
    |
    +---- COST
    |
    +---- RELIABILITY
             |
             +---- RDS Multi-AZ
             +---- S3 Lifecycle
             +---- EC2 Auto Scaling
```

Mock scanners provide offline implementations for development and demonstrations.

This architecture makes it easier to:

* Add new AWS services
* Add new security checks
* Add reliability checks
* Test scanners independently
* Run demonstrations without AWS
* Extend the project for automation
* Improve risk evaluation
* Generate consistent reports

---

# 🚧 Future Improvements

Potential future improvements include:

* Additional AWS service scanners
* AWS Config integration
* CloudTrail security analysis
* CloudWatch security monitoring
* Automated remediation
* CIS benchmark mapping
* Compliance framework support
* Continuous security monitoring
* CI/CD integration
* GitHub Actions integration
* Email security alerts
* Improved cost anomaly detection
* Advanced risk scoring
* Interactive security dashboards
* Historical scan comparison
* Multi-region scanning
* AI-assisted security recommendations
* Reliability scoring
* Availability and resilience trend analysis

---

# ⚠️ Disclaimer

CloudSentry is an educational and security-auditing project designed to help identify potentially insecure AWS configurations and reliability risks.

It should not be considered a replacement for a professional cloud security platform or a complete AWS security audit.

Always review findings before making changes to production infrastructure.

---

# 📌 Project Status

**Status: Active Development**

Current CloudSentry scanning areas:

```text
IAM
S3
EC2
VPC
COST
RELIABILITY
```

Reliability analysis currently includes:

```text
RDS Multi-AZ
S3 Lifecycle
EC2 Auto Scaling
```

CloudSentry currently supports:

* **AWS-based scanning**
* **Offline/mock scanning**
* **Centralized risk evaluation**
* **Security scoring**
* **JSON reporting**
* **HTML reporting**

The project is being developed toward a more comprehensive **cloud security, reliability, and automation platform**.

---

# 👨‍💻 Author

**Sahil Vats**

CloudSentry was developed as a cloud security and reliability project using:

**Java · Spring Boot · AWS SDK for Java · Picocli · Maven**

GitHub:

https://github.com/sahilvats327/CloudSentry

---

⭐ If you find the project interesting, consider giving the repository a star.
