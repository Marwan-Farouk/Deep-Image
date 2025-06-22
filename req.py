import subprocess
import sys

def install_requirements():
    try:
        # List of required packages
        required_packages = ["numpy","Pillow","pathlib"]

        print("Installing required packages...")
        for package in required_packages:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

        print("All requirements installed successfully!")
    except Exception as e:
        print(f"An error occurred while installing requirements: {e}")

if __name__ == "__main__":
    install_requirements()
