```
    +--------------------------------------------------------------------------------------+
    |8888888b.     d8888 888b    888  .d88888b.  8888888b. 88888888888 8888888888 .d8888b. |
    |888   Y88b   d88888 8888b   888 d88P" "Y88b 888   Y88b    888     888       d88P  Y88b|
    |888    888  d88P888 88888b  888 888     888 888    888    888     888       Y88b.     |
    |888   d88P d88P 888 888Y88b 888 888     888 888   d88P    888     8888888    "Y888b.  |
    |8888888P" d88P  888 888 Y88b888 888     888 8888888P"     888     888           "Y88b.|
    |888      d88P   888 888  Y88888 888     888 888           888     888             "888|
    |888     d8888888888 888   Y8888 Y88b. .d88P 888           888     888       Y88b  d88P|
    |888    d88P     888 888    Y888  "Y88888P"  888           888     8888888888 "Y8888P" |
    +--------------------------------------------------------------------------------------+
```

*An all-seeing, automated OSINT analysis and reporting tool*  
_by Alessandro Monetti (alessandromonetti@outlook.it)_

---

## Table of Contents

- [Project Overview](#project-overview)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
    - [Collect](#collect)
    - [Report](#report)
    - [Services](#services)
- [Output & Workspaces](#output--workspaces)
- [Screenshots](#screenshots)
- [Contributing & Support](#contributing--support)
- [License](#license)

---

## Project Overview

**Panoptes** (named after Argos Panoptes, the all-seeing giant of Greek mythology) automates the collection and analysis of Open Source Intelligence (OSINT) data for specified domains. Panoptes provides streamlined collection from multiple OSINT services and generates comprehensive reports, reducing manual work in intelligence gathering.

---

## Features

- Automated data collection for one or more domains via CLI
- Integration with well-known OSINT APIs (Shodan, VirusTotal, HaveIBeenPwned, IntelX, and more)
- Composable, filterable workflow (choose which services to run)
- Incremental reporting to process only new findings
- Multi-language reports (English, Italian)
- Themed PDF and HTML output
- **Manual report customization:** Export to PDF from a manually edited HTML report (see [`--export-from-html`](#report))
- Full workspace management (all data and reports organized by domain)

---

## Technology Stack
- **Python 3.8+**: Core language
- **Poetry**: Dependency management
- **Rich** & **Click**: CLI output
- **Requests**: HTTP requests to OSINT APIs
- **Jinja2**: Templating for HTML reports
- **WeasyPrint**: PDF generation from HTML
- **Typeguard**: Type checking for better code quality
- **Selenium**: Screenshots and web scraping
- **TQDM**: Progress bars file processing

--- 

## Installation

Panoptes uses [Poetry](https://python-poetry.org/) for package management. [pipx](https://pipx.pypa.io/) is recommended for isolated installs.

### Prerequisites

- Python 3.8+
- `poetry` installed ([Poetry installation guide](https://python-poetry.org/docs/#installation))

### Clone and Install

```sh
git clone https://github.com/ilveron/panoptes.git
cd panoptes
poetry install
```

---

## Configuration
Panoptes requires several environment variables to authenticate with various OSINT APIs. **Set these variables before running the application**:
(replace `xxx` with your actual API keys)
```sh
export INTELX="xxx"         # IntelX (API tier)
export HAVEIBEENPWNED="xxx" # HaveIBeenPwned (free)
export C99="xxx"            # C99 (paid)
export ABUSEIPDB="xxx"      # AbuseIPDB (free)
export VIRUSTOTAL="xxx"     # VirusTotal (free)
export SHODAN="xxx"         # Shodan (Freelancer tier)
export DNSDUMPSTER="xxx"    # DNSDumpster (free)
export MXTOOLBOX="xxx"      # MXToolbox (free)
export IMGBB="xxx"          # ImgBB (free)
```

You may wish to add these to your shell profile for convenience.

---

## Usage
Run Panoptes using Poetry:

### Activate the virtual environment
```sh
poetry env activate
```

### Run the CLI
```sh
poetry run python -m panoptes.cli <command> [OPTIONS]
```

(*You can create a script or alias if you prefer a shorthand like* `poetry run panoptes`.)

### Available Commands

- #### `services`
    
    List all available OSINT services and their descriptions.
    ```sh
    poetry run python -m panoptes.cli services
    ```
- #### `collect`

    Gather OSINT data for one or more domains.

    ```sh
    poetry run python -m panoptes.cli collect <domain1> [<domain2> ...] [OPTIONS]
    ```
    *Options*:

    - `--filter, -f`: Comma-separated list of services to run. Use `services` endpoint to view all.
    - `--mail-domain, -m`: (optional) Custom mail domain for data collection.
    - `--website-url, -w`: (optional) Website URL (defaults to `https://<domain>` or `https://www.<domain>`).

- #### `report`

    Generate (or update) an OSINT report for a collected domain.

    ```sh
    poetry run python -m panoptes.cli report <domain> [OPTIONS]    
    ```
    
    *Options*:

    - `--incremental`: Only process and report on new data since the last run.
    - `--language`: Output language for the report (en/it). Default: en.
    - `--export-from-html`: Export the report to PDF from the (possibly manually edited) HTML file found in the domain's workspace directory.
    Use this option if you wish to customize the HTML report before generating the final PDF.
    - `--theme`: Report styling (`iei` or `unical`). Default: `iei`.

---

## Output & Workspaces

- On first run, a `panoptes` directory is created in your home folder:
`~/panoptes/`

- For each new domain, a subdirectory (named after the domain) is created inside this folder.

- **Data collected** is stored as `JSON`. **Reports** (in HTML and PDF) are generated in the same workspace.

- Each new OSINT collection is merged with previous data for full history/context.

### Example Workspace Structure
```
~/panoptes/
    ├── example.com/
    │   ├── <service>/
    │   │   └── <data>.json
    │   ├── report.json
    │   ├── report-example-en.html
    │   ├── report-example-en.pdf
    │   ├── report-example-it.html
    │   └── report-example-it.pdf
    └── anotherdomain.org/
        ├── ...
```

---

## Screenshots

### Application
Here are some screenshots from the application:

#### `services` command
![Services command](https://i.imgur.com/AwaW8oc.png)

#### `collect` command
![Collect command](https://i.imgur.com/z7Ii3iD.png)

#### `report` command
![Report command](https://i.imgur.com/Jl3PoVI.png)

### Reports
Here are some excerpts from the generated reports:

(TO BE ADDED)

---

## License

This project is licensed under the `MIT License` - see the [LICENSE](LICENSE) file for details.