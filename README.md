# persistent-clientside-xss

## How to start the crawler       
run the following command from crawler_flow_finder folder:   

```
python3 crawler.py --database test.db --flows_dir flows --domains tranco-5k.txt --ip_addr localhost  --debug
```

The above will work only if you run the crawler and the tainted chrome on the same machine. if you run them on separate machines then change the localhost to be the ip address of the machine that runs the crawler.py.    

For example (my ip address in my local network: 192.168.20.87):    
```
python3 crawler.py --database test.db --flows_dir flows --domains tranco-5k.txt --ip_addr 192.168.20.87  --debug
```

The crawler scans by default the first 1000 domains from tranco-5k.txt. You can change this number by changing the DOMAIN_LIMIT parameter in crawler.py.     
Same goes for the depth of the crawler, the max number of urls per domain and the number of chrome tabs the crawler opens.

 

