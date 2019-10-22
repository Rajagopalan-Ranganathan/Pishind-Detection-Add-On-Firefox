# !/bin/bash

#kill all the previous instances
#kill $(ps aux | grep '[p]ython3 phishing_detector.py' | awk '{print $2}')
#kill $(ps aux | grep '[p]ython3 dispatcher.py' | awk '{print $2}')
#kill $(ps aux | grep '[p]ython3 target_identifier.py' | awk '{print $2}')


#change directory to the current one and the to the source
cd "$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd sources

#Launch the server with 2 target_id and 1 phishing_det
python3 dispatcher.py 2 1
