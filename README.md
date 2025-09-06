## Installations
```
cd /opt/  && sudo git clone https://github.com/h6nt3r/jshelper.git && cd jshelper/
sudo chmod +x *.py
sudo pip3 install -r requirements.txt --break-system-packages
cd
sudo ln -sf /opt/jshelper/jshelper.py /usr/local/bin/jshelper
jshelper -h
```
## Usage
#### Single url
```
jshelper -u "https://domain.com/file.js" -links -o jslinks.txt
```
#### File scanning mode
```
jshelper -f js_urls.txt -links -o jslinks.txt
```
