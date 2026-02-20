# TOSSS: an Extensible Benchmark for Evaluating the Security of LLM-Generated Code

With their increasing capabilities, Large Language Models (LLMs) are now used across many industries. They have become useful tools for software engineers to support a wide range of development tasks. As LLMs are increasingly used to generate or refine production code, a critical question arises: is LLM-generated code secure? At the same time, organizations worldwide invest heavily in cybersecurity to reduce exposure to disruptive attacks. Integrating LLM-generated code into software systems may introduce new vulnerabilities and weaken existing security efforts.

We introduce TOSSS (Two-Option Secure Snippet Selection), a benchmark that measures the ability of LLMs to choose between secure and vulnerable code snippets. Existing security benchmarks for LLMs cover only a limited range of vulnerabilities. In contrast, TOSSS relies on the CVE database and provides an extensible framework that can integrate newly disclosed vulnerabilities over time. Our benchmark gives each model a security score between 0 and 1 based on its behavior; a score of 1 indicates that the model always selects the secure snippet, while a score of 0 indicates that it always selects the vulnerable one. We evaluate several widely used open-source and closed-source models and observe scores ranging from 0.55 to 0.85. LLM providers already publish many benchmark scores for their models, and TOSSS could become a complementary security-focused score to include in these reports.

Paper: [TODO]

## Set-up

To install required dependencies, download and prepare benchmark datasets, we provide a script `setup.sh`.

Once setup is complete, run the benchmark pipeline: `python main.py`.

To add new models, you can update the file `config.json`.

## [TODO] Citation

If you use this framework, please cite:
@misc{toss_benchmark_2026,
title={Benchmarking LLM Security by Detecting Misleading Outputs and Promoting Compliance in High-Stakes Domains},
year={2025},
}
