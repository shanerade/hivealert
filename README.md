# What is it
Hivealert is a simple HTTP callback server to generate alerts in TheHive. This began as a need to generate TheHive alerts from Graylog using an HTTP callback and didn't have time to learn how to build graylog plugins. This has the added benefit of being called from anywhere to generate an alert, just add a route for it.

# Install
```bash
export HH=/opt/hivealert
sudo useradd hivealert -k /dev/null -m -d $HH
sudo -H -u hivealert git clone https://gitlab.com/shanerade/hivealert.git $HH/hivealert
cd $HH/hivealert
sudo -H -u hivealert pip3 install -r requirements.txt
sudo cp hivealert.service /etc/systemd/system
sudo systemctl daemon-reload
sudo systemctl enable hivealert && sudo systemctl start hivealert
```
# Note: Be sure to set the set the following values in `hivealert.py`:  
```
GRAYLOG = 'GRAYLOG_URL'
HIVE = 'HIVE_URL'
HIVE_API_KEY = 'HIVE_API_KEY'
```
