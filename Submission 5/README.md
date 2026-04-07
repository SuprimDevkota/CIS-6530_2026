
# Project Setup and Execution Guide - Submission 5

Although this project was done on Kaggle, it can be run locally provided there is accessed to a CUDA-enabled GPU. The following steps are required for running the project locally.

## 1. Extract the Project Files
Unzip the provided archive file to your desired location.

## 2. Navigate to the Project Directory
Open a terminal or command prompt and move into the project folder:

```bash
cd Submission_5
```

## 3. Create a Virtual Environment (Python ≥ 3.11)
Set up a virtual environment to manage dependencies:

```bash
python -m venv venv         # for Windows
python3 -m venv venv        # for macOS/Linux
```

## 4. Activate the Virtual Environment
Activate the virtual environment before installing dependencies:
```bash
venv\Scripts\activate       # for Windows
source venv/bin/activate    # for macOS/Linux
```

## 5. Install Dependencies
Install all required packages listed in requirements.txt:

```bash
pip install -r requirements.txt
```

## 6. Run the Project
Execute the CNN script:

```bash
python model_neural.py        
```

## Notes
- Ensure you are using Python 3.11 or higher.
- Always activate the virtual environment before running the project.
- If you encounter issues, verify that all dependencies installed correctly.
