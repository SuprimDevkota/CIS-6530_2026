## Repository Structure
```bash
.
├── Extracted_Instructions.zip/
│   ├── APT_Group_1/
│   │   ├── sample_1.instruction
│   │   └── sample_2.instruction
│   ├── APT_Group_2/
│   │   └── sample_1.instruction
│   └── ...
│
├── Extracted_Opcodes.zip/
│   ├── APT_Group_1/
│   │   ├── sample_1.opcode
│   │   └── sample_2.opcode
│   ├── APT_Group_2/
│   │   └── sample_1.opcode
│   └── ...
│
├── logs/
│   └── extraction.log
├── opcode_extraction_pipeline.py
├── Report.PDF
└── README.md
```

## Directory and File Descriptions

- `Extracted_Instructions.zip/`: This folder contains the disassembled assembly instructions extracted from the executable files. Every APT group has their own sub-directory which contains the actual instructions. (_We extracted these instructions separately because they could help us in future submissions._)

- `Extracted_Opcodes.zip/`: This folder contains the opcodes extracted from the executable files. Every APT group has their own sub-directory which contains the actual opcodes.

- `logs/extraction.log`: This log file was created by the script during execution. It was needed to identify root causes when encountering errors.

- `opcode_extraction_pipeline.py`: This is a custom multi-threaded script written in Python that sends the executable files to Ghidra in order to extract Opcodes and Instructions parallely.

- `Report.pdf`: This is the technical report that describes the implementation and usage of the script above.

## Intended Use and Environment Assumptions

This repository is intended to be used only by students or researchers with an understanding of malware handling and analysis.

If interaction with samples is required:

- Use a fully isolated virtual machine

- Ensure the environment has no network connectivity unless explicitly controlled

- Never extract or handle samples on a personal or production system

- Follow institutional and legal guidelines for malware research

## Responsible Disclosure and Handling
This repository does not promote malware development or misuse.
All samples are curated, stored, and presented responsibly for educational purposes only.

If you are unsure how to safely handle malware samples, do not extract or interact with the files.