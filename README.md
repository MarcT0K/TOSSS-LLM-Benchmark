# Benchmark - Code Vulnerability LLM

Benchmarking LLM Security by Detecting Misleading Outputs and Promoting Compliance in High-Stakes Domains

## Overview

This repository provides a framework to evaluate large language models (LLMs) in security-critical scenarios. It detects misleading or non-compliant outputs and benchmarks LLM performance in code vulnerability detection across different risk domains.

Benchmarks like WikiContradict already cover general LLM data poisoning. However, a domain-specific benchmark, more specifically in cybersecurity, has not gained as much traction. The embedding of LLMs in security tools has increased significantly, making it easier to negatively impact such models by misleading or poisoning data. The AI Act is entering the workforce and thus more reason to guide and regulate domain-specific misinformation.

**Key Features**

- Automated test suite for evaluating LLM responses
- Domain-specific benchmarks for high-stakes compliance
- Misleading output classification and scoring
- Easy-to-extend modular design

## Set-up

Run the following script to initialize the environment:

` bash ./setup.sh`

This script will install required dependencies, download and prepare benchmark datasets.

**[To Do]** Once setup is complete, run the benchmark pipeline:
`python run_benchmark.py --model <model_name> --domain <domain_name>`

**[To Do]** Examples:

- Run on a specific vulnerability domain:

  `python run_benchmark.py --model gpt-4 --domain web-injection`

- Evaluate multiple models:

  `python run_benchmark.py --model gpt-4,code-llama,mistral --domain all`

## **[To Do]** Extending Benchmarks

To add new models or compliance criteria:

- Modify scoring logic in `evaluation/`
- Add model configs in `models/`

## [To Do] Citation

If you use this framework, please cite:
@misc{benchmark-llm-vuln,
title={Benchmarking LLM Security by Detecting Misleading Outputs and Promoting Compliance in High-Stakes Domains},
year={2025},
publisher={OpenSecurityBench},
}
