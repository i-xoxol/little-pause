#!/usr/bin/env python3
"""Installed, trusted test entrypoint; run only as the isolated build user."""
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

def main():
    os.umask(0o077)
    base=Path('/var/lib/little-pause-build')
    archive=Path('/var/lib/little-pause-deploy/candidate.tar')
    with tempfile.TemporaryDirectory(prefix='candidate-',dir=base) as directory:
        with tarfile.open(archive,'r') as source:source.extractall(directory,filter='data')
        for command in [
            ['/usr/bin/python3','-m','unittest','discover','-v'],
            ['/usr/bin/node','--check','app.mjs'],
            ['/usr/bin/node','--check','crypto.mjs'],
            ['/usr/bin/node','--test','test_crypto.mjs'],
        ]:
            print('Checking:', ' '.join(command),flush=True)
            subprocess.run(command,cwd=directory,check=True,timeout=90)
    print('All candidate checks passed.',flush=True)

if __name__=='__main__':main()
