# Sec Your DevOps

*Mostly* platform-agnostic tools and resources for securing your development and operations environments. See the companion AWS repository at [sec-your-aws](https://github.com/vigah/sec-your-aws).

- [Tools](#tools)
  - [Application Security](#application-security)
  - [Source Code Management](#source-code-management)
  - [CI/CD](#cicd)
  - [Secrets](#secrets)
  - [Platform Security](#platform-security)
  - [Infrastructure as Code](#infrastructure-as-code)
  - [Cloud Security](#cloud-security)
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
- [Dastardly](https://github.com/PortSwigger/dastardly-github-action): Runs a scan using Dastardly by Burp Suite against a target site and creates a JUnit XML report for the scan on completion.
- [hijagger](https://github.com/firefart/hijagger): Checks all maintainers of all NPM and Pypi packages for hijackable packages through domain re-registration.
- [GuardDog](https://github.com/DataDog/guarddog): A CLI tool to identify malicious PyPI packages.

### Source Code Management

- [GitGat](https://github.com/scribe-public/gitgat): A tool to evaluate GitHub security posture.
- [policy-bot](https://github.com/palantir/policy-bot): A GitHub App that enforces approval policies on pull requests.
- [Github Analyzer](https://github.com/crashappsec/github-analyzer): A tool to check the security settings of Github Organizations.

### CI/CD

- [actionlint](https://github.com/rhysd/actionlint): Static checker for GitHub Actions workflow files.
- [Ratchet](https://github.com/sethvargo/ratchet): A tool for securing CI/CD workflows with version pinning.
- [GitHub Actions Importer](https://github.com/github/gh-actions-importer): Helps you plan and automate the migration of Azure DevOps, CircleCI, GitLab, Jenkins, and Travis CI pipelines to GitHub Actions.
- [GroovyWaiter](https://github.com/AnubisSec/GroovyWaiter): Jenkins enumeration and remediation tool.

### Secrets

- [Mozilla SOPS](https://github.com/mozilla/sops): Simple and flexible tool for managing secrets.
- [GitGuardian](https://www.gitguardian.com/): Scan Github repositories for secrets, CLI, CI/CD, PaaS.
- [git-secrets](https://github.com/awslabs/git-secrets): Prevents you from committing secrets and credentials into git repositories.
- [git-hound](https://github.com/tillson/git-hound): Reconnaissance tool for GitHub code search. Finds exposed API keys using pattern matching, commit history searching, and a unique result scoring system.
- [repo-supervisor](https://github.com/auth0/repo-supervisor): Scans GitHub repositories for security misconfigurations, passwords, and secrets.
- [TruffleHog](https://github.com/trufflesecurity/trufflehog): A tool to find credentials all over the place.
- [Gitleaks](https://github.com/zricethezav/gitleaks): A SAST tool for detecting and preventing hardcoded secrets in git repos.
- [Secrets Patterns DB](https://github.com/mazen160/secrets-patterns-db): The largest open-source database for detecting secrets, API keys, passwords, tokens, and more.

### Platform Security

- [Sysdig](https://github.com/draios/sysdig): Linux system exploration and troubleshooting tool with first class support for containers.
- [Syft](https://github.com/anchore/syft): CLI tool and library for generating a Software Bill of Materials from container images and filesystems.
- [Mozzila SSL Config](https://ssl-config.mozilla.org/): Secure SSL configuration generator.
- [Hadolint](https://github.com/hadolint/hadolint): Dockerfile linter, validate inline bash, written in Haskell.
- [Docker Bench for Security](https://github.com/docker/docker-bench-security): A script that checks for dozens of common best-practices around deploying Docker containers in production.
- [Inspec](https://github.com/inspec/inspec): Security and compliance testing framework with a human- and machine-readable language for comparing actual versus desired system state.
- [KubeEye](https://github.com/kubesphere/kubeeye): Finds various problems on Kubernetes, such as application misconfiguration, unhealthy cluster components and node problems.

### Infrastructure as Code

- [tfsec](https://github.com/aquasecurity/tfsec): Static analysis for Terraform code.
- [checkov](https://github.com/bridgecrewio/checkov): Static code analysis tool with coverage for Terraform, CloudFormation, Kubernetes/Helm, Dockerfiles, Serverless, and ARM templates.
- [terrascan](https://github.com/accurics/terrascan): Static code analysis tool with coverage for Terraform, Kubernetes/Helm, and Dockerfiles.
- [Azure Terrafy](https://github.com/Azure/aztfy): A tool to bring existing Azure resources under Terraform's management.
- [Terraform IAM Policy Validator](https://github.com/awslabs/terraform-iam-policy-validator): A command line tool that validates AWS IAM Policies in a Terraform template against AWS IAM best practice.
- [Pike](https://github.com/JamesWoolfenden/pike): A tool to determine the minimum permissions required for a Terraform run.

### Cloud Security

- [Cartography](https://github.com/lyft/cartography): A Python tool that consolidates infrastructure assets and the relationships between them in an intuitive graph view powered by a Neo4j database.
- [ScoutSuite](https://github.com/nccgroup/scoutsuite): Multi-cloud security auditing tool.
- [Cloud Custodian](https://github.com/cloud-custodian/cloud-custodian): Rules engine for cloud security, cost optimization, and governance, DSL in yaml for policies to query, filter, and take actions on resources.
- [Cloudlist](https://github.com/projectdiscovery/cloudlist): a tool for listing Assets from multiple Cloud Providers.

### Offensive Tools

- [Stratus Red Team](https://github.com/DataDog/stratus-red-team/): Granular, actionable adversary emulation for the cloud.
- [PurplePanda](https://github.com/carlospolop/PurplePanda): Identify privilege escalation paths within and across different clouds (currently supports GCP, GitHub, and Kubernetes)
- [Gato](https://github.com/praetorian-inc/gato): GitHub self-hosted runner enumeration and attack tool.

### Observability

- [DefectDojo](https://github.com/DefectDojo/django-DefectDojo): DevSecOps and vulnerability management tool.

## Methodology & Frameworks

- [NIST Software Supply Chain and DevOps Security Practices](/docs/NIST_Software_Supply_Chain_and_DevOps_Security_Practices.pdf)
- [CIS Software Supply Chain Security Guide v1.0](/docs/CIS_Software_Supply_Chain_Security_Guide_v1.0.pdf)
- [MITRE DevSecOps Best Practices Guide](/docs/MITRE_DevSecOps_Best_Practices_Guide_01262020.pdf)
- [DoD DevSecOps Fundamentals Guidebook](/docs/DoD_DevSecOps_Tools_Activities_Guidebook.pdf)
- [DoD Enterprise DevSecOps Reference Design](/docs/DoD_Enterprise_DevSecOps_Reference_Design.pdf)
- [CNCF Software Supply Chain Best Practices](https://github.com/cncf/tag-security/blob/main/supply-chain-security/supply-chain-security-paper/CNCF_SSCP_v1.pdf)
- [Common Threat Matrix for CI/CD](https://github.com/rung/threat-matrix-cicd): An ATT&CK-like matrix focused on CI/CD pipeline specific risk.
- [Cloud Security Orienteering Checklist](https://gist.github.com/ramimac/823e52befba373d71bc936d1742768f4): How to orienteer in a cloud environment, dig in to identify the risks that matter, and put together actionable plans that address short, medium, and long term goals.
- [Container Security Checklist](https://github.com/krol3/container-security-checklist): Checklist for container security and DevSecOps practices.
- [DevSecOps Playbook](https://github.com/6mile/DevSecOps-Playbook): A step-by-step guide to implementing a DevSecOps program for any size organization.

## Training

- [Actions by Example](https://www.actionsbyexample.com/): An introduction to GitHub actions through annotated examples.
- [OWASP WrongSecrets](https://github.com/commjoen/wrongsecrets): Pwnable application focused on secrets storage.
- [KustomizeGoat](https://github.com/bridgecrewio/kustomizegoat): Vulnerable Kustomize Kubernetes templates for training and education.
- [CI/CD Goat](https://github.com/cider-security-research/cicd-goat): A deliberately vulnerable CI/CD environment.
- [DevOps The Hard Way](https://github.com/AdminTurnedDevOps/DevOps-The-Hard-Way-AWS): Free labs for setting up an entire workflow and DevOps environment from a real-world perspective in AWS.
- [Container.Training](https://github.com/jpetazzo/container.training): Slides and code samples for training, tutorials, and workshops about Docker, containers, and Kubernetes.
- [TerraGoat](https://github.com/bridgecrewio/terragoat): A terraformed learning and training environment that demonstrates how common configuration errors can find their way into production cloud environments. Covers AWS, Azure, and GCP.
- [SadServers](https://sadservers.com/): A SaaS where users can test their Linux troubleshooting skills on real Linux servers in a "Capture the Flag" fashion.

## News & Social

- [tl;dr sec](https://tldrsec.com/): Best newsletter source for tools, blog posts, conference talks, and original research. By [Clint Gibler](https://twitter.com/clintgibler).
- [CloudSecList](https://cloudseclist.com/): A low volume newsletter (delivered once per week) that highlights security-related news focused on the cloud native landscape. By [Marco Lancini](https://twitter.com/lancinimarco).
- [Awesome Security Newsletters](https://github.com/TalEliyahu/awesome-security-newsletters): Newsletters and Twitter lists that capture the latest news, summaries of conference talks, research, best practices, tools, events, vulnerabilities, and analysis of trending threats and attacks.
- [InfoSec: Top 100 Tweeters](https://twitter.com/i/lists/901197194312769536): Curated by [@RayRedacted](https://twitter.com/RayRedacted).

## Other Lists

- [Open Source Security Index](https://opensourcesecurityindex.io/): A list of the most popular & fastest growing open source security projects on GitHub.
- [HOUDINI](https://github.com/cybersecsi/HOUDINI): Hundreds of offensive and useful Docker images for network intrusion.
- [Open Source Web Scanners](https://github.com/psiinon/open-source-web-scanners): A list of open source web security scanners sorted by GitHub stars.
- [Awesome DevOps](https://github.com/wmariuss/awesome-devops): A curated list of awesome DevOps tools, platforms and resources.
- [Application Security Tools](https://ishaqmohammed.me/posts/application-security-tools/): Curated list of free/open source application security tools.
- [Awesome Security Hardening](https://github.com/decalage2/awesome-security-hardening): A collection of awesome security hardening guides, tools and other resources.
- [Awesome Container Tinkering](https://github.com/iximiuz/awesome-container-tinkering): A list of tools to tinker with containers.
- [SSC Reading List](https://github.com/chainguard-dev/ssc-reading-list): A reading list for software supply-chain security.

## Books

- [Securing DevOps](https://www.amazon.com/dp/1617294136): by [Julien Vehent](https://twitter.com/jvehent).
- [Container Security: Fundamental Technology Concepts that Protect Containerized Applications](https://www.amazon.com/dp/1492056707): by [Liz Rice](https://twitter.com/lizrice).
