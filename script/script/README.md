README
======

Phishing Detection
------------------

This is a simple tool that used with our add-on allows you to detect in real-time phishing websites.
To proceed with the installation follow the instruction below.
At the end of the installation process, a page in which you will able to download the add-on will open.
You can also use the link listed below.

Notes
-----
* Written in Python 3.4
* Any and all comments and bug reports are welcome!


Requirements
------------
In order to install this tool you will need up to 150 Mb free.
To avoid slow down in the machine we recommend at least 2 Gb of RAM.

README
-----

Ubuntu installation
-------------------

sudo add-apt-repository ppa:fkrull/deadsnakes

sudo apt-get update

sudo apt-get install python3.4

sudo apt-get install python3-pip


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

installation of Tesseract OCR (https://code.google.com/p/tesseract-ocr/)

sudo apt-get install tesseract-ocr

sudo pip3 install autobahn==0.12.1

sudo pip3 install twisted==15.5.0

bash run.sh



Generate windows installer
--------------------------

Step 1
------

python 3.4
https://www.python.org/downloads/release/python-340/

and at least the following modules

pip3.4.exe install statistics==1.0.3.5

pip3.4.exe install requests==2.9.1

pip3.4.exe install beautifulsoup4==4.4.1

pip3.4.exe install selenium==2.49.0

pip3.4.exe install pandas==0.17.1

pip3.4.exe install publicsuffix==1.1.0

pip3.4.exe install goslate==1.5.1

pip3.4.exe install unidecode==0.4.18

pip3.4.exe install scikit-learn==0.17

pip3.4.exe install autobahn==0.12.1

pip3.4.exe install twisted==15.5.0

pip3.4.exe install setuptools==19.2

pip3.4.exe install pyinstaller

Numpy and Scipy are complex to install on windows, you'll have to look for them here:

http://www.lfd.uci.edu/~gohlke/pythonlibs/#numpy

http://www.lfd.uci.edu/~gohlke/pythonlibs/#scipy

Look for the correct package and install them with pip3.4 install <package>


Step 2
------

Check if those file are in the folder

model_xxx.pkl

hook-sklearn.tree.py


Step 3
------

Download and install the add-on

Chrome:

https://chrome.google.com/webstore/detail/off-the-hook/fibihpdighcmaiofgnigpbockiflaegp

Step 4
------

First build and check the installation

Repeat this command for:

phishing_detector.py

target_identificator.py

dispatcher.py

C:\Python34\Scripts\pyinstaller.exe <path_to_file> --onefile --additional-hooks-dir=.

Copy those files in dist:

data (folder)

model_xxx.pkl

Run and test

Step 5
------

First build and check the installation

Repeat this command for:

phishing_detector.py

target_identificator.py

dispatcher.py

C:\Python34\Scripts\pyinstaller.exe <path_to_file> --windowed --onefile --additional-hooks-dir=. --icon=phishing.ico

Copy those files in dist:

data (folder)

model_xxx.pkl

Run and test

Step 6
------
Install wix

http://wixtoolset.org/releases/

"C:\Program Files (x86)\WiX Toolset v4.0\bin\candle.exe" "Off the hook.wxs"

"C:\Program Files (x86)\WiX Toolset v4.0\bin\light.exe" "Off the hook.wixobj"

Run and test

Reboot and test

DONE

Bugs
----

Please report any bug to giovanni.armano(at)aalto.fi <br/>
If the system get too slow or you want to terminate the script run in this path <br/>
$ bash kill.sh