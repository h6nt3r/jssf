## Installations
```
cd /opt/  && sudo git clone https://github.com/h6nt3r/jshelper.git && cd jshelper/
sudo chmod +x *.py
sudo pip3 install -r requirements.txt --break-system-packages
cd
sudo ln -sf /opt/jshelper/jshelper.py /usr/local/bin/jshelper
jshelper -h
```
## Options
```
jshelper -h
usage: jshelper [-h] [-u URL] [-f FILE] [-o OUTPUT] [-links] [-secrets]

Extract links, paths, endpoints, and secrets from JavaScript files

options:
  -h, --help           show this help message and exit
  -u, --url URL        Target JavaScript file URL
  -f, --file FILE      File containing multiple JS URLs
  -o, --output OUTPUT  Output file (plain text)
  -links               Extract links from JS
  -secrets             Extract secrets from JS
```
## Usage
#### Piping mode
```
echo "https://domain.com/secret.js" | jshelper -links -o jslinks.txt
```
#### Single url
```
jshelper -u "https://domain.com/file.js" -links -o jslinks.txt
```
#### File scanning mode
```
jshelper -f js_urls.txt -links -o jslinks.txt
```
