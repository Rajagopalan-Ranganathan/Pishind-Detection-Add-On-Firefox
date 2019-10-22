# !/bin/bash

kill $(ps aux | grep '[p]ython3 phishing_detector.py' | awk '{print $2}')
kill $(ps aux | grep '[p]ython3 dispatcher.py' | awk '{print $2}')
kill $(ps aux | grep '[p]ython3 target_identifier.py' | awk '{print $2}')
