from subprocess import Popen
import sqlite3
import csv
import asyncio
import websockets
import json
import tldextract
import sys
import time
import argparse
import os
from multiprocessing import Process

'''
run command:

python3 crawler.py --database test.db --flows_dir flows --domains tranco-5k.txt   --debug

This backend crawler listens for a conneciton from chrome on port localhost:8787.
It then waits to receive a start message from chrome like so:
{"start_crawl": 1}
After that it starts sending urls to chrome in a json format like so (a single url per message):
{"url": "www.google.com"}
and receives from chrome replies ("links", "flow" and "close" are optional per message):
{ 
  "url": "www.google.com",
  "links": ["www.google.com/link1", "www.google.com/link2", "www.google.com/link3"]
  "flow": "......" 
  "close": 1     // this means that chrome finished processing the url and retrieved all links and all flows for this url. This must be sent eventually for every url!
}
'''

#parameters for crawler, can be modified for your own comfort
DOMAIN_LIMIT = 1000 #the amount of domains from tranco-5k.txt to scan
PORT = 8787 
MAX_URL_DEPTH = 2  #the depth of the scan
MAX_NUM_URLS_PER_DOMAIN = 1000 #the number of urls to scan for each domain
MAX_OUTSTANDING_URLS = 20 #the number of tabs to open in chrome while crawling

#------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------
#initializing parameters

flows_dir = ""
websocket_to_chrome = None
outstanding_urls = 0
debug = False
con = None # database connection
urls_to_send = []
#------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------

def log(msg):
    global debug 
    if debug:
        print(msg)
        
no_fetch_extract = tldextract.TLDExtract(suffix_list_urls=["file:///public_suffix_list.dat"])
        
def open_db(database_file):
    con = sqlite3.connect(database_file)
    cur = con.cursor()
    # check if database is new
    res = cur.execute("SELECT name FROM sqlite_master")
    log(f"Database {database_file} is open.")
    if res.fetchone() is not None: #not new
        log(f"Database is not new.")
        return con
    log(f"Database is new.")
    #initialize the tables
    cur.execute("CREATE TABLE urls(domain TEXT, url TEXT PRIMARY KEY, depth INTEGER, scanned INTEGER)")
    cur.execute("CREATE TABLE flows(url TEXT, hash TEXT PRIMARY KEY)")
    log(f"Tables created.")
    return con


def seed_db(con, domains):
    log(f"Seeding db.") 
    cur = con.cursor()
    with open(domains) as csvfile:
        domainreader = csv.reader(csvfile)
        data = []
        for row in domainreader:
            if int(row[0]) > DOMAIN_LIMIT:
                break
                
            ext = no_fetch_extract(row[1])
            row_link_domain = ".".join([ext.domain, ext.suffix])
            log(f"the link domain is: " + row_link_domain);
            
            data.append((row_link_domain, row[1], 0, 0))
            log(f"Found {row[1]} is domain seed file.")
            
        
        
        cur.executemany("INSERT OR IGNORE INTO urls VALUES(?, ?, ?, ?)", data)
        con.commit()
        log(f"Database seeded with domains.")

def mark_scanned_url(con, cur, url):
    log(f"mark the url: {url} as scanned")
    res = cur.execute(f'SELECT domain, depth, scanned FROM urls WHERE url="{url}"')
    url_entry = res.fetchall()
    assert(len(url_entry) == 1) #checks that there is only one instance of this url in the data base
    (url_domain, url_depth, url_scanned) = url_entry[0]
    assert(url_depth <= MAX_URL_DEPTH)
    #Mark the url as scanned
    if not url_scanned:
        log(f"Mark {url} as scanned.")
        cur.execute(f'UPDATE urls SET scanned = 1 WHERE url="{url}"')
        log("marked the url: {url} as scanned")
        con.commit()


def process_links(con, cur, url, links):
    log(f"Processing links for {url}.")
    #log(links)
    # Get the url from db amke sure it is in the db
    res = cur.execute(f'SELECT domain, depth, scanned FROM urls WHERE url="{url}"')
    url_entry = res.fetchall()
    #log(f'the url entry we got is: "{url_entry[0]}"');
    log(f'the number of lines we got is: "{len(url_entry)}"');
    log(f"the current url is: {url}")
    log(len(url_entry))
    
    #sometimes the urls are dynamically changing so we get a different url from the background script. in
    #that case theres not much to do but to just drop the case. the code technically is not supposed to
    #even #get to this line because most times in this case we wont even get flows or links
    if len(url_entry) == 0:
        log(f"there are no links in this url(there are no links in ba-sing-se)")
        return
        
    assert(len(url_entry) == 1) #checks that there is only one instance of this url(it means that I 
                                # have to check in the back script that there is no double urls
    (url_domain, url_depth, url_scanned) = url_entry[0]
    assert(url_depth <= MAX_URL_DEPTH)
    
    #Mark the url as scanned
    if not url_scanned:
        log(f"Mark {url} as scanned.")
        cur.execute(f'UPDATE urls SET scanned = 1 WHERE url="{url}"')
        con.commit()
        
    if url_depth >= MAX_URL_DEPTH:
        log(f"Url is already at maximum depth. No deeper links will be added.")
        return
    
    #Get all urls for the domain of url
    res = cur.execute(f'SELECT url FROM urls WHERE domain="{url_domain}"')
    urls_aready_found = res.fetchall()
    num_urls_aready_found_for_domain = len(urls_aready_found)
    log(f"Number of urls already found for domain {url_domain} is {num_urls_aready_found_for_domain}.")
    if num_urls_aready_found_for_domain >= MAX_NUM_URLS_PER_DOMAIN:
        log(f"Exceeded urls per domain. Nothing to do.")
        return
    num_links_till_limit = MAX_NUM_URLS_PER_DOMAIN - num_urls_aready_found_for_domain
    links_to_insert = []
    candidate_links = set(links).difference(urls_aready_found)
    #log(f"Candidate links are {candidate_links}.")
    log("showing candidate links")
    for link in candidate_links:
        log(f"processing link {link}.")
        ext = no_fetch_extract(link)
        link_domain = ".".join([ext.domain, ext.suffix])
        
        log(f"the url_domain is: {url_domain}")
        log(f"the link_domain is: {link_domain}")
        
        if url_domain == link_domain:
            links_to_insert.append((link_domain, link, url_depth+1, 0))
            log(f"Appended {link}.")
            num_links_till_limit = num_links_till_limit - 1
            if num_links_till_limit <= 0:
                log(f"Reached maximum links per domain.")
                break
    cur.executemany("INSERT OR IGNORE INTO urls VALUES(?, ?, ?, ?)", links_to_insert)
    con.commit()


def process_flow(con, cur, url, flow):
    global flows_dir
    log(f"Processing flow for {url}.")
    #log(flow)
    # Get the url from db make sure it is in the db
    res = cur.execute(f'SELECT domain, depth, scanned FROM urls WHERE url="{url}"')
    url_entry = res.fetchall()
    
 
    if len(url_entry) == 0:
        log(f"there are no links in this url")
        return
    
    assert(len(url_entry) == 1)
    
    #compute hash for flow
    flow_hash = str(hash(flow))
    cur.execute("INSERT OR IGNORE INTO flows VALUES(?, ?)", (url, flow_hash))
    flow_file = os.path.join(flows_dir, flow_hash + ".json")
    log(f"Saving file {flow_file}.")
    with open(flow_file, "w", encoding="utf8") as outfile:
        outfile.write(flow)
    con.commit()


async def send_urls(websocket, cur):
    global outstanding_urls
    global urls_to_send
    #takes the urls from the database and stores them in urls_to_send. note: urls_to_send is always of 
    #size 1 because of the return false in the end
    while outstanding_urls < MAX_OUTSTANDING_URLS:
        if len(urls_to_send) == 0:
            log("No more urls. Fetching new ones from db.")
            res = cur.execute(f"SELECT url FROM urls WHERE scanned = 0")
            urls_to_send.extend(res.fetchall())
            log(f"Fetched {len(urls_to_send)} urls.")
            #log(urls_to_send)
            if len(urls_to_send) == 0:
                log("No more urls to crawl. Exiting.")
                return True
        url = urls_to_send.pop()
        log(f"Sending {url}....")
        msg = {'url': str(url[0]) }
        msg = json.dumps(msg)
        #msg = f'{{"url": "{url[0]}"}}'
        
        await websocket.send(msg)
        #log(f"Sent {msg}.")
        outstanding_urls = outstanding_urls + 1
        log(f"Outstanding urls {outstanding_urls}.")
    return False 
    

async def process_start(websocket, cur):
    global websocket_to_chrome
    websocket_to_chrome = websocket
    log(f"Got start.")
    await send_urls(websocket, cur)

#gets messages from chrome
async def process_message(websocket):
    global outstanding_urls
    global con
    cur = con.cursor()
    async for message in websocket:
        #log(f"Got message {message}.") # we dont display the actual message because it can be long
        m = json.loads(message)
        if "start_crawl" in m:
            await process_start(websocket, cur)
            continue
        url = m["url"]
        if "ping" in m: #because apperently the websocket decides to just close for no reason when it isnt getting any messages
            log("got ping")    
            continue           
        log(f"Got message from url: {url}"); 
        if "links" in m:
            links = m["links"]
            if len(links) > 0:
                process_links(con, cur, url, links)
        if "flow" in m:
            flow = m["flow"]
            if len(flow) > 0:
                process_flow(con, cur, url, flow)
        if "close" in m:
            mark_scanned_url(con, cur, url) #mark the url as scanned
            log(f"Got url close from url: {url}")
            outstanding_urls = outstanding_urls - 1 
            log(f"Outstanding urls {outstanding_urls}.")
            stop = await send_urls(websocket, cur)
            if stop:
                return
        
           
async def websocket_server():
    async with websockets.serve(process_message, "localhost", PORT, ping_interval=None, max_size = 100000000000):
        await asyncio.Future()  # run forever


def main(): 
    # Launch chrome
    parser = argparse.ArgumentParser()
    parser.add_argument('--database', type=str, required=True,
                        help='Enter database (sqllite) filename that stores all content')
    parser.add_argument('--flows_dir', type=str, required=True,
                        help='Enter the path to directiory where all flow files will be saved')
    parser.add_argument('--domains', type=str, required=True,
                        help='Enter the path to the file that contains the domains to crawl')
    parser.add_argument('--debug', dest='debug', action='store_true')
    args = parser.parse_args()
    
    global flows_dir
    flows_dir = args.flows_dir
    global debug
    debug = args.debug

    # Init DB
    global con
    con = open_db(args.database)
    cur = con.cursor()
    seed_db(con, args.domains)
    
    log(f"Starting websocket server.")
    #Launch websocket server
    asyncio.run(websocket_server())
 
            
    
 
 
if __name__ == '__main__':
    main()
