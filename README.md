\# CloudSentry



CloudSentry is an AWS cloud security scanning CLI built with Java, Spring Boot, AWS SDK for Java, and Picocli.



It analyzes AWS security configurations across IAM, S3, EC2, and VPC and generates security findings with severity levels, recommendations, risk scoring, and JSON reports.



\## Features



\- AWS security scanning using AWS SDK for Java

\- Offline/mock scanning mode for development and demonstration

\- IAM security analysis

\- S3 security analysis

\- EC2 security analysis

\- VPC security analysis

\- HIGH, MEDIUM, and LOW severity classification

\- Overall security score and risk level

\- Severity filtering

\- JSON security report generation

\- CLI exit codes for security automation

\- Spring Boot based architecture

\- Picocli command-line interface



\## Security Coverage



\### IAM



CloudSentry currently includes checks for:



\- Root account MFA

\- Root access keys

\- User MFA

\- Access key age

\- Access key usage

\- Inline IAM policies

\- Managed IAM policies

\- Group policies

\- Password policy

\- AdministratorAccess

\- Multiple active access keys

\- Inactive access keys

\- Privilege escalation actions



\### S3



Current S3 checks include:



\- Public access block configuration

\- Bucket encryption

\- Versioning

\- Logging

\- HTTPS-only access

\- Public bucket policies

\- Cross-account access

\- Object ownership

\- Public write/delete access



\### EC2



Current EC2 checks include:



\- Public security group access

\- EBS volume encryption

\- Public IP exposure

\- IMDSv2 enforcement

\- Termination protection

\- Public EBS snapshots

\- EBS snapshot encryption

\- Sensitive port exposure

\- Unrestricted outbound traffic

\- Public IPv6 security-group access

\- Public AMI exposure

\- Unencrypted EBS volumes



\### VPC



Current VPC checks include:



\- Public subnet exposure

\- Internet Gateway detection

\- Default security group exposure

\- Network ACL exposure

\- VPC Flow Logs

\- Public IPv6 routes



\## Architecture



```text

&#x20;                   CloudSentry CLI

&#x20;                         |

&#x20;                   Spring Boot

&#x20;                         |

&#x20;                    ScanService

&#x20;                         |

&#x20;            +------------+------------+

&#x20;            |            |            |

&#x20;           IAM           S3          EC2

&#x20;            |            |            |

&#x20;            +------------+------------+

&#x20;                         |

&#x20;                        VPC

&#x20;                         |

&#x20;                   Security Findings

&#x20;                         |

&#x20;                     Risk Engine

&#x20;                         |

&#x20;                 +-------+-------+

&#x20;                 |               |

&#x20;            Console Report    JSON Report

