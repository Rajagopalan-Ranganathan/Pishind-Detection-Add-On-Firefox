# !/bin/bash

#python3.4 installation
sudo add-apt-repository ppa:fkrull/deadsnakes
sudo apt-get update
#sudo apt-get install python3.4
#sudo apt-get install python3-pip

#python modules
sudo pip3 install statistics==1.0.3.5
sudo pip3 install requests==2.9.1
sudo pip3 install beautifulsoup4==4.4.1
sudo pip3 install selenium==2.49.0
sudo pip3 install numpy==1.10.4
sudo pip3 install pandas==0.17.1
sudo pip3 install publicsuffix==1.1.0
sudo pip3 install goslate==1.5.1
sudo pip3 install unidecode==0.4.18
sudo apt-get build-dep python3-scipy
sudo pip3 install scipy==0.16.1
sudo pip3 install scikit-learn==0.17
sudo apt-get install libxml2-dev libxslt1-dev
sudo apt-get install python3-lxml

# installation of Tesseract OCR (https://code.google.com/p/tesseract-ocr/)
sudo apt-get install tesseract-ocr

sudo pip3 install autobahn==0.12.1
sudo pip3 install twisted==15.5.0

#installation of other software
sudo apt-get install screen
sudo chmod 777 run.sh

#add run.sh to auto execution
#echo @reboot sudo screen -dmS Phishing bash $(pwd)/run.sh | sudo tee -a /etc/cron.d/anacron
(sudo crontab -u root -l; echo @reboot screen -dmS Phishing bash $(pwd)/run.sh ) | sudo crontab -u root -
