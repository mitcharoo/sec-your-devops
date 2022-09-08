# Sec Your DevOps

- [Tools](#tools)
  - [Application Security](#application-security)
  - [CI/CD Security](#cicd-security)
  - [Secrets](#secrets)
  - [Platform Security](#platform-security)
  - [Infrastructure as Code](#infrastructure-as-code)
  - [Cloud Security](#cloud-security)
  - [Amazon Web Services](#amazon-web-services)
  - [Microsoft Azure](#microsoft-azure)
  - [Google Cloud Platform](#google-cloud-platform)
  - [Offensive Tools](#offensive-tools)
  - [Observability](#observability)
- [Methodology & Frameworks](#methodology--frameworks)
- [Training](#training)
- [News & Social](#news--social)
- [Other Lists](#other-lists)
- [Books](#books)

## Tools

### Application Security

- [Semgrep](https://github.com/returntocorp/semgrep): Static analysis tool for finding bugs and enforcing code standards at editor, commit, and CI time.
- [SonarQube](https://github.com/SonarSource/sonarqube): Continuous inspection tool for code quality and security.
- [Snyk](https://snyk.io/): Static analysis of code, container images, and IaC. CLI, IDE, CI/CD, PaaS.
- [OWASP Zed Attack Proxy (ZAP)](https://www.zaproxy.org/docs/docker/baseline-scan/): Popular penetration testing tool that can also be leveraged within CI/CD to perform passive baseline scans.
- [ShiftLeft](https://www.shiftleft.io/): PaaS SAST and SCA tool offering scheduled and CI/CD initiated testing.
- [AllStar](https://github.com/ossf/allstar): Github app to set and enforce repository security policies
- [It-Depends](https://github.com/trailofbits/it-depends): A tool to automatically build a dependency graph and Software Bill of Materials (SBOM) for packages and arbitrary source code repositories.
- [Trivy](https://github.com/aquasecurity/trivy): Scanner for vulnerabilities in container images, file systems, and Git repositories, as well as for configuration issues.
- [ClusterFuzzLite](https://github.com/google/clusterfuzzlite): Simple continuous fuzzing that runs in CI.
- [Scorecard](https://github.com/ossf/scorecard): Security health metrics for open source.
- [jfrog-npm-tools](https://github.com/jfrog/jfrog-npm-tools): A collection of tools to help audit your NPM dependencies for suspicious packages or continuously monitor dependencies for future security events.
- [policy-bot](https://github.com/palantir/policy-bot): A GitHub App that enforces approval policies on pull requests.

### CI/CD Security

- [GitHub Action: Configure AWS Credentials](https://github.com/aws-actions/configure-aws-credentials): Configure AWS credential environment variables for use in other GitHub Actions.

### Secrets

- [Mozilla SOPS](https://github.com/mozilla/sops): Simple and flexible tool for managing secrets.
- [GitGuardian](https://www.gitguardian.com/): Scan Github repositories for secrets, CLI, CI/CD, PaaS.

### Platform Security

- [Sysdig](https://github.com/draios/sysdig): Linux system exploration and troubleshooting tool with first class support for containers.
- [Syft](https://github.com/anchore/syft): CLI tool and library for generating a Software Bill of Materials from container images and filesystems.
- [Mozzila SSL Config](https://ssl-config.mozilla.org/): Secure SSL configuration generator.
- [Hadolint](https://github.com/hadolint/hadolint): Dockerfile linter, validate inline bash, written in Haskell.
- [Docker Bench for Security](https://github.com/docker/docker-bench-security): A script that checks for dozens of common best-practices around deploying Docker containers in production.
- [Inspec](https://github.com/inspec/inspec): Security and compliance testing framework with a human- and machine-readable language for comparing actual versus desired system state.

### Infrastructure as Code

- [tfsec](https://github.com/aquasecurity/tfsec): Static analysis for Terraform code.
- [checkov](https://github.com/bridgecrewio/checkov): Static code analysis tool with coverage for Terraform, CloudFormation, Kubernetes/Helm, Dockerfiles, Serverless, and ARM templates.
- [terrascan](https://github.com/accurics/terrascan): Static code analysis tool with coverage for Terraform, Kubernetes/Helm, and Dockerfiles.
- [Azure Terrafy](https://github.com/Azure/aztfy): A tool to bring existing Azure resources under Terraform's management.

### Cloud Security

- [Cartography](https://github.com/lyft/cartography): A Python tool that consolidates infrastructure assets and the relationships between them in an intuitive graph view powered by a Neo4j database.
- [ScoutSuite](https://github.com/nccgroup/scoutsuite): Multi-cloud security auditing tool.
- [Cloud Custodian](https://github.com/cloud-custodian/cloud-custodian): Rules engine for cloud security, cost optimization, and governance, DSL in yaml for policies to query, filter, and take actions on resources.

### Amazon Web Services

- [Prowler](https://github.com/prowler-cloud/prowler): Open source security tool to perform AWS security best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness.
- [AWS Security Toolbox](https://github.com/z0ph/aws-security-toolbox): Single Docker container combining several popular security tools.
- [Quiet Riot](https://github.com/righteousgambit/quiet-riot): Unauthenticated enumeration of services, roles, and users in an AWS account or in every AWS account in existence.
- [CloudMapper](https://github.com/duo-labs/cloudmapper): Helps analyze your AWS environments, including auditing for security issues.
- [aws-security-viz](https://github.com/anaynayak/aws-security-viz): Visualize your AWS security groups.
- [AWS CloudSaga](https://github.com/awslabs/aws-cloudsaga): Test security controls and alerts within AWS, using generated alerts based on security events seen by the AWS Customer Incident Response Team (CIRT).
- [cloud-nuke](https://github.com/gruntwork-io/cloud-nuke): A tool for cleaning up your AWS accounts by nuking (deleting) all resources within it.
- [CloudTracker](https://github.com/duo-labs/cloudtracker): Helps you find over-privileged IAM users and roles by comparing CloudTrail logs with current IAM policies.
- [PMapper](https://github.com/nccgroup/PMapper): A tool for quickly evaluating IAM permissions in AWS.
- [CloudJack](https://github.com/prevade/cloudjack): Route53/CloudFront vulnerability assessment utility.
- [Sandcastle](https://github.com/0xSearches/sandcastle): A Python script for AWS S3 bucket enumeration.
- [Security Hub Automated Response & Remediation](https://github.com/aws-solutions/aws-security-hub-automated-response-and-remediation): An add-on solution that works with AWS Security Hub to provide a ready-to-deploy architecture and a library of automated playbooks.
- [s3tk](https://github.com/ankane/s3tk): A security toolkit for AWS S3.
- [CDK-Dia](https://github.com/pistazie/cdk-dia): Automated diagrams of AWS CDK provisioned infrastructure.
- [Aaia](https://github.com/rams3sh/Aaia): AWS IAM visualizer and anomaly finder.
- [domain-protect](https://github.com/ovotech/domain-protect): Discover and protect against subdomain takeover vulnerabilities in AWS & Cloudflare.
- [awspx](https://github.com/FSecureLABS/awspx): A graph-based tool for visualizing effective access and resource relationships in AWS environments.
- [Metabadger](https://github.com/salesforce/metabadger): Automated EC2 Instance Metadata Service upgrade to v2 (IMDSv2).
- [Remediate AWS IMDSv1](https://github.com/latacora/remediate-AWS-IMDSv1): Simple tool to identify and remediate the use of the AWS EC2 IMDSv1.
- [LocalStack](https://github.com/localstack/localstack): Local AWS cloud emulator.
- [cloud-nuke](https://github.com/gruntwork-io/cloud-nuke): A tool for cleaning up your AWS accounts by nuking (deleting) all resources within it.
- [Assisted Log Enabler](https://github.com/awslabs/assisted-log-enabler-for-aws): Find AWS resources that are not logging and turn them on.
- [aws-vault](https://github.com/99designs/aws-vault): A vault for securely storing and accessing AWS credentials in development environments. 

### Microsoft Azure

- [Azucar](https://github.com/nccgroup/azucar): Security auditing tool for Azure environments.

### Google Cloud Platform

### Offensive Tools

- [Pacu](https://github.com/RhinoSecurityLabs/pacu): An AWS exploitation framework.
- [Stratus Red Team](https://github.com/DataDog/stratus-red-team/): Granular, actionable adversary emulation for the cloud.
- [PurplePanda](https://github.com/carlospolop/PurplePanda): Identify privilege escalation paths within and across different clouds (currently supports GCP, GitHub, and Kubernetes)

### Observability

## Methodology & Frameworks

- [MITRE DevSecOps Best Practices Guide](/docs/MITRE_DevSecOps_Best_Practices_Guide_01262020.pdf)
- [DoD DevSecOps Fundamentals Guidebook](/docs/DoD_DevSecOps_Tools_Activities_Guidebook.pdf)
- [DoD Enterprise DevSecOps Reference Design](/docs/DoD_Enterprise_DevSecOps_Reference_Design.pdf)
- [CNCF Software Supply Chain Best Practices](https://github.com/cncf/tag-security/blob/main/supply-chain-security/supply-chain-security-paper/CNCF_SSCP_v1.pdf)
- [Common Threat Matrix for CI/CD](https://github.com/rung/threat-matrix-cicd): An ATT&CK-like matrix focused on CI/CD pipeline specific risk.
- [Cloud Security Orienteering Checklist](https://gist.github.com/ramimac/823e52befba373d71bc936d1742768f4): How to orienteer in a cloud environment, dig in to identify the risks that matter, and put together actionable plans that address short, medium, and long term goals.
- [Container Security Checklist](https://github.com/krol3/container-security-checklist): Checklist for container security and DevSecOps practices.
- [DevSecOps Playbook](https://github.com/6mile/DevSecOps-Playbook): A step-by-step guide to implementing a DevSecOps program for any size organization.
- [Azure Threat Research Matrix](https://microsoft.github.io/Azure-Threat-Research-Matrix/): Knowledge base built to document known TTPs within Azure and Azure AD.

## Training

- [Mandiant Azure Workshop](https://github.com/mandiant/Azure_Workshop): A vulnerable-by-design Azure lab containing 2 x attack paths with common misconfigurations.
- [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable): Use Terraform to create your own vulnerable by design AWS IAM privilege escalation playground.
- [Actions by Example](https://www.actionsbyexample.com/): An introduction to GitHub actions through annotated examples.
- [OWASP WrongSecrets](https://github.com/commjoen/wrongsecrets): Pwnable application focused on secrets storage.
- [KustomizeGoat](https://github.com/bridgecrewio/kustomizegoat): Vulnerable Kustomize Kubernetes templates for training and education.
- [CI/CD Goat](https://github.com/cider-security-research/cicd-goat): A deliberately vulnerable CI/CD environment.
- [DevOps The Hard Way](https://github.com/AdminTurnedDevOps/DevOps-The-Hard-Way-AWS): Free labs for setting up an entire workflow and DevOps environment from a real-world perspective in AWS.
- [Container.Training](https://github.com/jpetazzo/container.training): Slides and code samples for training, tutorials, and workshops about Docker, containers, and Kubernetes.
- [S3 Game Galaxy](https://master.d2av1kz25zeu6f.amplifyapp.com/): A series of challenges to learn S3 features.

## News & Social

- [tl;dr sec](https://tldrsec.com/): Best newsletter source for tools, blog posts, conference talks, and original research. By [Clint Gibler](https://twitter.com/clintgibler).
- [CloudSecList](https://cloudseclist.com/): A low volume newsletter (delivered once per week) that highlights security-related news focused on the cloud native landscape. By [Marco Lancini](https://twitter.com/lancinimarco).
- [This Week in Security](https://this.weekinsecurity.com/): A weekly tl;dr cybersecurity newsletter of all the major stuff you missed, but really need to know. By [Zach Whitaker](https://twitter.com/zackwhittaker).
- [Awesome Security Newsletters](https://github.com/TalEliyahu/awesome-security-newsletters): Newsletters and Twitter lists that capture the latest news, summaries of conference talks, research, best practices, tools, events, vulnerabilities, and analysis of trending threats and attacks.
- [InfoSec: Top 100 Tweeters](https://twitter.com/i/lists/901197194312769536): Curated by [@RayRedacted](https://twitter.com/RayRedacted).
- [AWS Security Blog](https://aws.amazon.com/blogs/security/): Official announcements, product highlights, and walk-throughs. Optional mailing list.

## Other Lists

- [HOUDINI](https://github.com/cybersecsi/HOUDINI): Hundreds of offensive and useful Docker images for network intrusion.
- [AWS Customer Security Incidents](https://github.com/ramimac/aws-customer-security-incidents): A repository tracking known breaches of AWS customers.
- [AWS Security Arsenal](https://github.com/toniblyx/my-arsenal-of-aws-security-tools): List of open source tools for AWS security: defensive, offensive, auditing, DFIR, etc.
- [Open Source Web Scanners](https://github.com/psiinon/open-source-web-scanners): A list of open source web security scanners sorted by GitHub stars.
- [Awesome DevOps](https://github.com/wmariuss/awesome-devops): A curated list of awesome DevOps tools, platforms and resources.
- [Application Security Tools](https://ishaqmohammed.me/posts/application-security-tools/): Curated list of free/open source application security tools.
- [Awesome Security Hardening](https://github.com/decalage2/awesome-security-hardening): A collection of awesome security hardening guides, tools and other resources.
- [SSC Reading List](https://github.com/chainguard-dev/ssc-reading-list): A reading list for software supply-chain security.

## Books

- [Securing DevOps](https://www.amazon.com/dp/1617294136): by [Julien Vehent](https://twitter.com/jvehent).
- [Security and Microservice Architecture on AWS: Architecting and Implementing a Secured, Scalable Solution](https://www.amazon.com/dp/1098101464): by Gaurav Raje.
- [Container Security: Fundamental Technology Concepts that Protect Containerized Applications](https://www.amazon.com/dp/1492056707): by [Liz Rice](https://twitter.com/lizrice).
