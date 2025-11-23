# Security-in-Computing-and-IT
## Assignment 1: Analytical Security Report
## Student Name: Phyu Phyu Shinn Thant (Zyra)
## Student ID: S4022136
## Course: Security in Computing & IT (RMIT Vietnam)

### Project Overview
This repository contains the source code and experimental data used for Assignment 1: Analytical Security Report. The project benchmarks the performance of various cryptographic primitives across three categories, namely hashing, symmetric encryption, asymmetric encryption, and quantum computing algorithms. 

### Repository Contents
security_benchmark.py: Main script for data generation, encryption, and benchmarking.
comparative_results.csv: Generated dataset containing performance metrics.

### Installation
Kali Linux with Python version 3.13 on Intel Core Ultra 9.
Install dependencies:
pip install cryptography psutil tabulate post-quantum-crypto-toolkit

### Usage
Run the script to perform validation checks and benchmarks:
**python3 comparative_analysis.py**
The script outputs a summary table to the console and updates the CSV file, comparative_results.csv
