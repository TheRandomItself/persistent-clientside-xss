//need to get the urls from the socket
//stores all the initial links and the links are being added every time
var initial_links = ["https://www.google.com/"];//contains the domains that we start with
var url_links = [["https://www.google.com/"]]; //contains the urls for every tab
var single_tab_links = []; //temporarily contains the urls of a tab
var visited_urls = []; 
var TIMEOUT = 30000
//listens for connections from the content script
chrome.runtime.onConnect.addListener(function(port) {
 //listens for a message from the content script. the message in this case informs if the url in the tab we got the message from is an exploit or not
  port.onMessage.addListener(function(msg, sendingPort) {
     
      if (msg.data_type == "flows"){
  
            var the_final_url = port.name;
            if (window.url_map[sendingPort.sender.tab.id]){
                the_final_url = window.url_map[sendingPort.sender.tab.id];
           
            if (msg.data_flows){
                 
                 var chrome_reply = {
                                 "url": the_final_url,
                                 "flow": msg.data_flows
                };

                if (JSON.stringify(chrome_reply).length > 100000){
                    console.log("flows message length is: " + JSON.stringify(chrome_reply).length);
                }
                else{
                     websocket.send(JSON.stringify(chrome_reply));
                }
            }
           
         }
         }   
      
      if (msg.data_type == "links"){

            var new_links = removeDoubles(msg.hyperURLs);
            
            var the_final_url = port.name;
            if (window.url_map[sendingPort.sender.tab.id]){
                the_final_url = window.url_map[sendingPort.sender.tab.id];

            }
            
            var hyper_links_urls = [];
            if (msg.hyperURLs){
               hyper_links_urls = msg.hyperURLs;
            }
            var chrome_reply = {
      
                                 "url": the_final_url,
                                 "links": hyper_links_urls 
            };
            if (JSON.stringify(chrome_reply) > 1000000){
                console.log("links message length is: " + JSON.stringify(chrome_reply).length);
            }
            websocket.send(JSON.stringify(chrome_reply));
         
      }
  });

});

chrome.runtime.onInstalled.addListener(function() {
    window.url_map = { "tabUrl": "realUrl" }; //for every tab we store the url that opened it
    console.log("entered listener");
    window.websocket = new WebSocket("ws://localhost:8787");
    websocket.onerror = function(evt) { onError(evt) };
    websocket.onopen = function(evt) { onOpen(evt) };
    websocket.onclose = function(evt) { onClose(evt) };
    websocket.onmessage = function(evt) { onMessage(evt) };

});

function onError(evt){
    console.log("the connection failed");
}

function onOpen(evt){
    websocket.send(JSON.stringify({"start_crawl": 1}));
}

function onClose(evt){
    console.log("the connection is closed");
}

function onMessage(evt){
    var msg = evt.data;
    var obj_msg = JSON.parse(msg);

    //creates a new tab
    chrome.tabs.create({url: obj_msg.url}, function(tab){
 
    console.log(tab);
    window.url_map[tab.id] = obj_msg.url;
 
        setTimeout(closeSession, TIMEOUT, tab);//waits 30 seconds before sending to the crawler to close the tabs
    });

}

//just in case we want to ping to the crawler(currently not working)
function first_iteration(tab){
    var ping_web_socket = {
                        "url": tab.url,
                         "ping": "ping"
    };
    websocket.send(JSON.stringify(ping_web_socket));
    setTimeout(second_iteration, 13000, tab);
}

function second_iteration(tab){
    var ping_web_socket = {
                        "url": tab.url,
                         "ping": "ping"
    };
    websocket.send(JSON.stringify(ping_web_socket));
    setTimeout(closeSession, 13000, tab);
}

function closeSession(tab){

    chrome.tabs.remove(tab.id, function(){
    });

    var theurl = tab.url;
    if(window.url_map[tab.id]){
        theurl = window.url_map[tab.id];
        console.log(window.url_map[tab.id]);
    }
    var chrome_reply = {
                        "url": theurl,
                         "close": 1
    };
    websocket.send(JSON.stringify(chrome_reply));
    
}

function findElement(value, array){
    for(var i = 0; i < array.length; i++)
    {
        if (array[i] == value)
            return true;
    }
    return false;
}



function foundElement(array, value){
    for(var i = 0; i < array.length; i++){
        if (array[i] == value)
           return true;
    }
    return false;
}

//returns an array without doubles
function removeDoubles(links_arr){
    var new_links = [];
    for(var i = 0; i < links_arr.length; i++){
        if (foundElement(new_links, links_arr[i]) == false)
            new_links.push(links_arr[i]);
    }
    return new_links;
}






