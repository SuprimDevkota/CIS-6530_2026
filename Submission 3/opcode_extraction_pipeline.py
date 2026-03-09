#!/usr/bin/env python3

# Automated Opcode and Instruction Extraction Pipeline
#
# This script performs automated opcode and full instruction extraction from malware samples using Ghidra Headless Analyzer.
#
# Script Features:
# - Automates batch processing of malware samples
# - Temporary Ghidra project creation
# - Opcode extraction
# - Full instruction extraction
# - Classification of extraction outcomes
# - Structured logging
# - Timeout handling
# - Automatic cleanup of temporary artifacts
# - Failure-safe pipeline
# - Multi-threaded execution
#

#------------------------------------------------------
# Imports
#------------------------------------------------------
import os
import subprocess
import logging
import shutil
import uuid
import argparse
from concurrent.futures import ThreadPoolExecutor


# --------------------------------------------------------
# Global Statistics
# --------------------------------------------------------

stats = {
    "total": 0,
    "success": 0,
    "packed": 0,
    "obfuscated": 0,
    "failed": 0,
    "timeout": 0,
    "skipped": 0
}


# --------------------------------------------------------
# Logging Setup
# --------------------------------------------------------

def setup_logging():
    """
    Initializes structured logging for the execution pipeline.
        - Creates logs directory if missing
        - Logs are written to logs/extraction.log

    Log Levels:
        INFO    -> Successful extraction
        WARNING -> Packed/suspicious/unsupported
        ERROR   -> Timeout or execution failure
    """

    if not os.path.exists("logs"):
        os.makedirs("logs")

    logging.basicConfig(
        filename="logs/extraction.log",
        filemode="a",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )


# --------------------------------------------------------
# Generate Temporary Ghidra Script
# --------------------------------------------------------

def create_ghidra_script(script_dir):
    """
    Creates a modular Ghidra Jython script used for extracting opcode mnemonics and full assembly instructions from a disassembled binary program.

    The generated script will be executed inside the Ghidra Headless Analyzer environment. 
    It performs instruction extraction and writes the results to output files specified as script arguments.

    Parameters    
        script_dir : str
            Directory where the generated Ghidra script will be stored.

    Returns
        Path to the generated Ghidra extraction script.
    
    Script Functions
        is_supported_executable() - check the executable format
        get_all_instructions() - retrieves instructions from the program listing
        extract_opcodes() - extracts opcode mnemonics and writes opcodes to files
        extract_instructions() - extracts full instructions and writes instructions to files
        ensure_directory() - make sure directories exist

    Workflow of the script
        1. Retrieve output file paths from script arguments
        2. Access the current program loaded in Ghidra
        3. Retrieve all instructions
        4. Extract opcode mnemonics and full instructions
        5. Write extracted data to output files
    """

    script_path = os.path.join(script_dir, "extract_opcodes.py")

    script_content = r'''
# @runtime Jython

import os

def is_supported_executable(program):
    executable_format = program.getExecutableFormat()

    if executable_format is None:
        return False

    if "Disk Image" in executable_format:
        return False

    if "XCOFF" in executable_format:        
        return True
      
    return True

def get_all_instructions(program):
    listing = program.getListing()
    return listing.getInstructions(True)


def extract_opcodes(instructions, opcode_output):

    with open(opcode_output, "w") as f:

        for instr in instructions:
            try:
                mnemonic = instr.getMnemonicString()
                f.write(mnemonic + "\n")
            except:
                continue


def extract_instructions(program, instr_output):

    instructions = get_all_instructions(program)

    with open(instr_output, "w") as f:

        for instr in instructions:
            try:
                f.write(str(instr) + "\n")
            except:
                continue

def ensure_directory(path):

    directory = os.path.dirname(path)

    if directory and not os.path.exists(directory):
        os.makedirs(directory)


def main():
    args = getScriptArgs()

    if len(args) != 2:
        return

    opcode_output = args[0]
    instr_output = args[1]

    program = currentProgram

    if program is None:
        return

    if not is_supported_executable(program):
        return

    # Ensure output directories exist
    ensure_directory(opcode_output)
    ensure_directory(instr_output)

    # Retrieve instruction iterator
    instructions = get_all_instructions(program)

    # Extract opcode mnemonics
    extract_opcodes(instructions, opcode_output)

    # Extract full instructions
    extract_instructions(program, instr_output)
	
if __name__ == "__main__":
    main()
'''

    with open(script_path, "w") as f:
        f.write(script_content)

    return script_path


# --------------------------------------------------------
# Sample Collection
# --------------------------------------------------------

def collect_samples(sample_dir):
    """
    Recursively collects all files in the sample directory.

    Parameters:
        sample_dir (str): Root directory containing malware samples.

    Returns:
        samples (list[str]): List of absolute file paths to samples.

    Important:
        - Samples are hash-named without extensions.
        - Therefore, we collect ALL files and let Ghidra determine executable format internally.
    """

    samples = []

    for root, _, files in os.walk(sample_dir):
        for file in files:
            full_path = os.path.join(root, file)
            samples.append(full_path)

    return samples


# --------------------------------------------------------
# Unique Project Creation
# --------------------------------------------------------

def create_unique_project():
    """
    Creates a temporary unique Ghidra project.

    Returns:
        tuple:
            project_root (str): Path to project directory.
            project_name (str): Ghidra project name.

    Rationale:
        - Avoid project collisions
        - Ensure isolation between samples and enable safe multi-thread execution
    """

    unique_id = str(uuid.uuid4())
    project_root = os.path.join("opcode_extraction_projects", unique_id)
    project_name = "proj_" + unique_id

    os.makedirs(project_root, exist_ok=True)

    return project_root, project_name


# --------------------------------------------------------
# Classification Logic
# --------------------------------------------------------

def classify_extraction(sample_path, output_file):
    """
    Classifies extraction outcome using heuristic instruction count analysis.

    Parameters:
        sample_path (str): Original sample file path.
        output_file (str): Generated opcode file path.

    Returns:
        None

    Heuristics:
        - 0 instructions     -> Failed disassembly
        - < 50 instructions  -> Possible packing
        - > 1,000,000        -> Possible obfuscation
        - Otherwise          -> Successful extraction
    """
    
    if not os.path.exists(output_file):
        stats["skipped"] += 1
        logging.warning(f"SKIPPED OR UNSUPPORTED FORMAT: {sample_path}")
        return

    try:
        with open(output_file, "r") as f:
            count = sum(1 for _ in f)

        if count == 0:
            stats["failed"] += 1
            logging.warning(f"NO INSTRUCTIONS: {sample_path}")

        elif count < 50:
            stats["packed"] += 1
            logging.warning(f"POSSIBLE PACKED (low instruction count={count}): {sample_path}")

        elif count > 1000000:
            stats["obfuscated"] += 1
            logging.warning(f"POSSIBLE OBFUSCATED (very high instruction count={count}): {sample_path}")

        else:
            stats["success"] += 1
            logging.info(f"SUCCESS (instruction count={count}): {sample_path}")

    except Exception:
        stats["failed"] += 1
        logging.error(f"FAILED DURING CLASSIFICATION: {sample_path}")


# --------------------------------------------------------
# Process Sample
# --------------------------------------------------------

def process_sample(ghidra_path, script_dir, script_name, sample_path, opcode_output_dir, instruction_output_dir):
    """
    Executes headless analysis a malware sample.

    Parameters:
        ghidra_path (str): Path to analyzeHeadless binary.
        script_dir (str): Directory containing extraction script.
        sample_path (str): Full path to malware sample.
        opcode_output_dir (str): Directory for generated opcode files.
        instruction_output_dir (str): Directory for generated instruction files.

    Workflow:
        1. Validate sample
        2. Create temporary project
        3. Run headless analysis
        4. extract opcode + instructions
        5. Perform classification
        6. Log results
        7. Clean up project
    """

    stats["total"] += 1

    if os.path.getsize(sample_path) == 0:
        stats["skipped"] += 1
        logging.warning(f"SKIPPED (zero-byte file): {sample_path}")
        return

    project_root, project_name = create_unique_project()

    sample_name = os.path.basename(sample_path)

    opcode_output_file = os.path.join(opcode_output_dir, sample_name + ".opcode")
    instruction_output_file = os.path.join(instruction_output_dir, sample_name + ".instruction")

    cmd = [
        ghidra_path,
        project_root,
        project_name,
        "-import", sample_path,
        "-scriptPath", script_dir,
        "-postScript", script_name, opcode_output_file, instruction_output_file,
        "-overwrite",
        "-analysisTimeoutPerFile", "1800"
    ]

    try:
        subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2000
        )

        classify_extraction(sample_path, opcode_output_file)

    except subprocess.TimeoutExpired:
        stats["timeout"] += 1
        logging.error(f"TIMEOUT (analysis exceeded limit): {sample_path}")

    except subprocess.CalledProcessError:
        stats["failed"] += 1
        logging.error(f"FAILED (Ghidra execution error): {sample_path}")

    finally:
        if os.path.exists(project_root):
            shutil.rmtree(project_root)


# --------------------------------------------------------
# Log Summary
# --------------------------------------------------------

def log_group_summary(group_name, stats):
    """    
    Logs structured extraction statistics for a completed APT group.

    Parameters:
        group_name (str): Name of the APT group being processed.
        stats (dict): Dictionary containing extraction statistics with keys:
            - total
            - success
            - packed
            - obfuscated
            - failed
            - timeout
            - skipped

    Behavior:
        - Writes a clearly formatted summary block into logs/extraction.log
        - Provides per-group metrics after batch processing completes
        - Ensures results are appended (not overwritten)

    Rationale:
        - Enables group-level performance evaluation
        - Supports reproducibility and structured reporting
        - Facilitates comparison across multiple APT groups
        - Prevents reliance on console output for critical metrics
    """

    logging.info("====================================================")
    logging.info(f"APT GROUP SUMMARY: {group_name}")
    logging.info("----------------------------------------------------")
    logging.info(f"Total       : {stats['total']}")
    logging.info(f"Success     : {stats['success']}")
    logging.info(f"Packed      : {stats['packed']}")
    logging.info(f"Obfuscated  : {stats['obfuscated']}")
    logging.info(f"Failed      : {stats['failed']}")
    logging.info(f"Timeout     : {stats['timeout']}")
    logging.info(f"Skipped     : {stats['skipped']}")
    logging.info("====================================================\n")


# --------------------------------------------------------
# Cleanup Temporary Artifacts
# --------------------------------------------------------

def cleanup_temp_artifacts(script_dir):
    """
    Removes temporary artifacts created during pipeline execution.

    Parameters:
        script_dir (str): Directory containing the temporary Ghidra script.

    Cleanup Actions:
        - Delete temporary Ghidra script directory
        - Delete root Ghidra project directory if empty
    """

    # Remove temporary Ghidra script directory
    if os.path.exists(script_dir):
        shutil.rmtree(script_dir, ignore_errors=True)

    # Remove root project directory if empty
    project_root_dir = "opcode_extraction_projects"

    if os.path.exists(project_root_dir) and not os.listdir(project_root_dir):
        os.rmdir(project_root_dir)


# --------------------------------------------------------
# MAIN
# --------------------------------------------------------

def main():
    """
    Workflow:
        1. Parses CLI arguments.
        2. Initializes logging.
        3. Make sure directories exits and if not create them
        4. Creating ghidra script
        5. Collects samples.
        6. Executes multi-threaded processing.
        7. Add structured log summary to extraction.log
        8. Cleanup temporary artifcats
    """
    
    parser = argparse.ArgumentParser(description="Automated Ghidra Headless Opcode Extraction")

    parser.add_argument("--ghidra", required=True, help="Path to analyzeHeadless")
    parser.add_argument("--samples", required=True, help="Folder containing malware samples")
    parser.add_argument("--opcodes", required=True, help="Output folder for .opcode files")
    parser.add_argument("--instructions", required=True, help="Output folder for .instruction files")
    parser.add_argument("--threads", type=int, default=4, help="Number of parallel threads")

    args = parser.parse_args()

    # Initialize logging
    setup_logging()

    group_name = os.path.basename(os.path.normpath(args.samples))

    #  Create group specific output directories
    opcode_group_dir = os.path.join(args.opcodes, group_name)
    instruction_group_dir = os.path.join(args.instructions, group_name)

    # Ensure output directories exist
    os.makedirs(opcode_group_dir, exist_ok=True) 
    os.makedirs(instruction_group_dir, exist_ok=True)    
    os.makedirs("opcode_extraction_projects", exist_ok=True)

    script_dir = "temp_script"
    os.makedirs(script_dir, exist_ok=True)
    ghidra_script = create_ghidra_script(script_dir)
    script_name = os.path.basename(ghidra_script)

    # Collect all samples
    samples = collect_samples(args.samples)

    print(f"[+] Processing APT Group: {group_name}")
    print(f"[+] Found {len(samples)} samples.")

    # Process samples
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(
                process_sample,
                args.ghidra,
                script_dir,
                script_name,
                sample,
                opcode_group_dir,
                instruction_group_dir
            )
            for sample in samples
        ]

        # Ensure all threads complete
        for f in futures:
            f.result()

    # Log structured group summary
    log_group_summary(group_name, stats)

    # Cleanup temporary artifacts
    cleanup_temp_artifacts(script_dir)

    print("[+] Extraction completed.")
    print("[+] Temporary scripts cleaned.")
    print("[+] All temporary Ghidra projects cleaned.")
    print("[+] Summary written to logs/extraction.log")
    print("[+] Done.")


if __name__ == "__main__":
    main()
