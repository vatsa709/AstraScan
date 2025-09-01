# 🚀 AstraScan: Intelligent API Discovery & Misconfiguration Scanner

AstraScan is an intelligent, command-line tool designed to discover and audit API endpoints for common security misconfigurations and vulnerabilities. By combining an automated endpoint fuzzer, a recursive crawler, and a powerful analysis engine, it helps you uncover hidden attack surfaces and security flaws in your APIs with a single command.

---

## ✨ Key Features

- **Smart Endpoint Discovery:** Probes for common API paths and then recursively crawls discovered endpoints to find a wider attack surface.  
- **API Misconfiguration Analysis:** Identifies a wide range of misconfigurations, including sensitive debug information, permissive HTTP methods, and insecure configurations.  
- **Unauthenticated Access Detection:** Automatically checks if discovered endpoints are accessible without a valid authentication token, highlighting critical authorization flaws.  
- **Sensitive Data Exposure:** Scans API responses for patterns that could indicate sensitive data leaks, such as email addresses, API keys, or credit card numbers.  
- **Security Header & CORS Analysis:** Audits HTTP headers like HSTS, CSP, and X-Frame-Options, and checks for dangerous CORS misconfigurations.  
- **Information Disclosure:** Identifies common information leaks in responses, such as stack traces, server banners, and internal IP addresses.  
- **Zombie API Detection:** By providing an OpenAPI/Swagger specification file, AstraScan can identify documented but unused or deprecated endpoints (Zombie APIs).  
- **GraphQL Introspection & Query Fuzzing:** Detects if GraphQL introspection is enabled and generates and tests sample queries to identify potential vulnerabilities.  
- **Parameter Fuzzing:** Injects common payloads into URL query parameters to test for vulnerabilities like SQL Injection or unexpected server behavior.  
- **Inferred OpenAPI Specification:** Automatically generates a basic OpenAPI specification based on discovered endpoints, helping you document your API.  
- **CI/CD Integration:** The `--ci-mode` flag allows for easy integration into your continuous integration pipeline, failing the build if high-risk issues are found.  

---

## ⚙️ Installation

To get started with AstraScan, follow these simple steps.

### 1. Clone the repository
```bash
git clone https://github.com/vatsa709/AstraScan.git
cd AstraScan
````

### 2. Create a Python Virtual Environment

```bash
# For Linux / macOS
python3 -m venv venv
source venv/bin/activate

# For Windows
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies

You'll need the `httpx` and `click` libraries.
Create a `requirements.txt` file in the project's root directory and add the following:

```
httpx
click
jinja2
```

Then, install them:

```bash
pip install -r requirements.txt
```

---

## 🔍 Usage

The scanner is controlled via the command line with various options to customize your scan.

### ▶️ Basic Scan

The most basic scan requires only the target URL:

```bash
python main.py --url https://api.example.com
```

### 🔑 Scan with Authentication

If your API requires authentication, you can provide an authorization token:

```bash
python main.py --url https://api.example.com --token "Bearer your-token-here"
```

### 🛠️ Run All Advanced Features

Use the `--all` flag to enable all available advanced scanning features in one go:

```bash
python main.py --url https://api.example.com --all -o reports/full_report.html
```

---

## 🎛️ Specific Command Flags

| Flag                | Description                                                                                                                                      | Example                         |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------- |
| `--url`             | **(Required)** The base URL of the API to scan.                                                                                                  | `--url https://api.example.com` |
| `--token`           | Provides an authorization token for authenticated scans.                                                                                         | `--token "Bearer abc123def456"` |
| `--graphql`         | Enables GraphQL introspection and query fuzzing.                                                                                                 | `--graphql`                     |
| `--documented-spec` | Path to an OpenAPI spec to detect Zombie APIs.                                                                                                   | `--documented-spec spec.json`   |
| `--output`          | Sets the output path and filename for the report. Supports `.html` and `.json`.                                                                  | `-o reports/my_report.json`     |
| `--ci-mode`         | Runs in CI/CD mode. The script will exit with code 1 if any high-risk issue is found.                                                            | `--ci-mode`                     |
| `--min-risk`        | **(New)** Filters the generated report to only show findings at or above a specified risk level. Valid options: `high`, `medium`, `low`, `info`. | `--min-risk high`               |
| `--max-depth`       | Limits the depth of recursive crawling.                                                                                                          | `--max-depth 3`                 |
| `--no-verify-ssl`   | Disables SSL certificate verification (use with caution).                                                                                        | `--no-verify-ssl`               |
| `--wordlist`        | Path to a custom wordlist for endpoint discovery.                                                                                                | `-w my_wordlist.txt`            |

---

## 📊 Understanding the Report

AstraScan generates a detailed **HTML report** by default, which is saved in the `reports/` directory.

The report provides:

* A comprehensive summary of the scan.
* Tables for each finding type (Misconfigurations, Sensitive Data, CORS, etc.).
* Detailed information on each issue, including affected URL, method, and reason.
* An inferred OpenAPI specification of the discovered endpoints.
* Actionable recommendations to help you fix the identified vulnerabilities.

---

## 🤝 Contributing

1. Fork this repository.
2. Create your feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m "Add a new feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a Pull Request.

---

## 👨‍💻 Author

AstraScan was created by **SRIVATSA**.

---

## 📜 License

This project is licensed under the **MIT License**.


