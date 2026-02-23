# Malware Sample Collection
#### ⚠️ IMPORTANT SAFETY NOTICE – DO NOT EXECUTE ⚠️

This repository contains real malware samples collected strictly for academic analysis and research purposes. Under no circumstances should any files in this repository be executed on a host system.

All malware samples are:

- Stored in password-protected archives.
- Provided to support malware research, attribution, and threat intelligence coursework

Failure to follow safe handling practices may result in system compromise.

## Intended Use and Environment Assumptions

This repository is intended to be used only by students or researchers with an understanding of malware handling and analysis.

If interaction with samples is required:

- Use a fully isolated virtual machine

- Ensure the environment has no network connectivity unless explicitly controlled

- Never extract or handle samples on a personal or production system

- Follow institutional and legal guidelines for malware research

## Repository Structure
```bash
.
├── Executable Malware 1/
│   ├── APT_Group_1/
│   │   ├── sample_1
│   │   └── sample_2
│   ├── APT_Group_2/
│   │   └── sample_1
│   └── ...
│
├── Executable Malware 2/
│   ├── APT_Group_1/
│   │   ├── sample_1
│   │   └── sample_2
│   ├── APT_Group_2/
│   │   └── sample_1
│   └── ...
│
├── Executable Malware 3/
│   ├── APT_Group_1/
│   │   ├── sample_1
│   │   └── sample_2
│   ├── APT_Group_2/
│   │   └── sample_1
│   └── ...
│
├── Executable Malware 4/
│   ├── APT_Group_1/
│   │   ├── sample_1
│   │   └── sample_2
│   ├── APT_Group_2/
│   │   └── sample_1
│   └── ...
│
├── Other Payloads/
│   ├── APT_Group_1/
│   │   └── payload_1
│   ├── APT_Group_3/
│   │   └── payload_1
│   └── ...
│
├── Malware_Metadata.xlsx
├── Methodology.docx
└── README.md
```
(_The Executable Malware ZIP is split into four to overcome GitHub's individual file limits._)

## Directory and File Descriptions

- `Executable Malware 1/`:  Contains executable malware samples (e.g., EXE, DLL) for groups **G0062 TA459** to **G0012 Darkhotel**. Every APT group has their own sub-directory which contains the actual samples.

- `Executable Malware 2/`:  Contains executable malware samples (e.g., EXE, DLL) for groups **G0126 Higaisa** to **G0020 Equation**. Every APT group has their own sub-directory which contains the actual samples.

- `Executable Malware 3/`:  Contains executable malware samples (e.g., EXE, DLL) for groups **G0041 Strider** to **G0094 Kimsuky**. Every APT group has their own sub-directory which contains the actual samples.

- `Executable Malware 4/`:  Contains executable malware samples (e.g., EXE, DLL) for groups **G0032 Lazarus Group** and **G0086 Stolen Pencil**. Every APT group has their own sub-directory which contains the actual samples.

- `Other Payloads/`: Contains non-executable or secondary payloads, such as scripts and loaders. Every APT group has their own sub-directory which contains the actual samples.

- `Malware_Metadata.xlsx`: An Excel spreadsheet documenting metadata for each malware sample, including APT group, hash, type, source and reasoning behind attribution.

- `Methodology.docx`: A written methodology describing the process used to complete this submision.


## Responsible Disclosure and Handling
This repository does not promote malware development or misuse.
All samples are curated, stored, and presented responsibly for educational purposes only.

If you are unsure how to safely handle malware samples, do not extract or interact with the files.