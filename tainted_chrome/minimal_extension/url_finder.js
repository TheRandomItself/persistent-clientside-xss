console.log("entered url finder");

console.log("entered listener");
setTimeout(loadLinks, 6000);//to give extra time for the links to load

//reads page content to find links and sends them to the background page 
function loadLinks(){
    console.log("starting to send links");
    var x = document.querySelectorAll("a");
    var links = [];
    for (var i = 0; i < x.length; i++) {
        var nametext = x[i].textContent;
        var cleantext = nametext.replace(/\s+/g, ' ').trim();
        var cleanlink = x[i].href;
        links[i] = cleanlink.toString();

    }
    var final_links = { 
                        data_type: "links", 
                        hyperURLs: links,
                        url: window.location.href
    };

    console.log("sending links");
    port = chrome.runtime.connect({name: window.location.href});
    port.postMessage(final_links);
}
