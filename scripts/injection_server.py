#!/usr/bin/env python3
"""
Alias — the canonical server is injection_classifier.py.
Run that file directly or use the install script.
"""
import subprocess, sys, os
here = os.path.dirname(os.path.abspath(__file__))
subprocess.run([sys.executable, os.path.join(here, "injection_classifier.py")] + sys.argv[1:])
