# !/bin/bash

#kill all the active instances
bash kill.sh

#remove the entry from crontab
sudo crontab -u root -l | grep -v '@reboot screen -dmS Phishing bash'  | sudo crontab -u root -