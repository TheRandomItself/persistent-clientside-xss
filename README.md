# persistent-clientside-xss

How to start the crawler:
run the crawler.py from the same folder:
python3 crawler.py --database test.db --flows_dir flows --domains tranco-5k.txt --ip_addr [YOUR IP ADDRESS]   --debug

for example (my ip address in my local network: 192.168.20.87):
python3 crawler.py --database test.db --flows_dir flows --domains tranco-5k.txt --ip_addr 192.168.20.87  --debug

or(in case youre running the crawler and the tainted chrome on the same machine):
python3 crawler.py --database test.db --flows_dir flows --domains tranco-5k.txt --ip_addr localhost  --debug

The crawler scans by default the first 1000 domains from tranco-5k.txt. you can change this number by changing the DOMAIN_LIMIT parameter in crawler.py
Same goes for the depth of the crawler, the max number of urls per domain and the number of tabs the crawler opens

