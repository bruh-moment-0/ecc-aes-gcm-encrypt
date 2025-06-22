import subprocess
import sys

libraries = {
    'cryptography': {'install': 'cryptography', 'import': 'cryptography'},
    'pycryptodome': {'install': 'pycryptodome', 'import': 'Crypto'},
}

def install(libraries):
    for name, lib in libraries.items():
        try:
            __import__(lib['import'])
            print(f"{name} is already installed.")
        except ImportError:
            print(f"{name} is not installed. Installing...")
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', lib['install']])
                print(f"{name} installed successfully.")
            except subprocess.CalledProcessError:
                print(f"Failed to install {name}. Please check your environment and try again.")
                continue
            except FileNotFoundError:
                print("pip not found. Installing pip...")
                try:
                    subprocess.check_call([sys.executable, '-m', 'ensurepip'])
                    print("pip installed successfully.")
                except subprocess.CalledProcessError:
                    print("Failed to install pip. Please check your environment and try again.")
                    continue

print("Press ENTER to start the installer:")
input()
install(libraries)
print("Done installing the required libraries.")
print("Press ENTER to exit.")
input()