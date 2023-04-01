console.log('aInjecting Helper functionality into ', window.location.href);
window.finding_id = 0;
console.log('val2', finding_id);
var sc = document.createElement('script');
window.flows = [];
window.flows_index = 0;
/////////////////////////////////////////////////////////////////////////////////////
/*function addFlows(finding){
    console.log("------------entered function------------------");
    window.flows[window.flows_index] = finding;
    window.flows_index = window.flows_index + 1;
    console.log("currrent flows: " + window.flows);
}*/

sc.textContent = '(' + (function(){
window.getSourcename = function (sourceId) {
    switch (sourceId) {
        case 0:
            return "benign";
        case 1:
            return "document.location.href";
        case 2:
            return "document.location.pathname";
        case 3:
            return "document.location.search";
        case 4:
            return "document.location.hash";
        case 5:
            return "document.URL";
        case 6:
            return "document.documentURI";
        case 7:
            return "document.baseURI";
        case 8:
            return "document.cookie";
        case 9:
            return "document.referrer";
        case 10:
            return "document.domain";
        case 11:
            return "window.name";
        case 12:
            return "postMessage";
        case 13:
            return "localStorage";
        case 14:
            return "sessionStorage";
        case 255:
            return "unknown";
        default:
            return "unknown code" + sourceId;
    }
};

window.download = function (content, fileName, contentType) {
    var a = document.createElement("a");
    var file = new Blob([content], {type: contentType});
    a.href = URL.createObjectURL(file);
    a.download = fileName;
    a.click();
	
};

window.getSourceInfo = function (finding_id, source, value, start, end) {
    var sourcePart = value.substring(start, end);
    if (source === 255) {
        var hasEscaping = 0;
        var hasEncodeURI = 0;
        var hasEncodeURIComponent = 0;
        var realSource = source;
        var isSameFrame = 1;
        var sourcename = getSourcename(realSource);
    } else {
        var hasEscaping = (source >> 4) & 1;
        var hasEncodeURI = (source >> 5) & 1;
        var hasEncodeURIComponent = (source >> 6) & 1;
        var realSource = source & 15;
        var sourcename = getSourcename(realSource);
        var isSameFrame = 1;
        if (source >> 7 == 1) // MSB is set to 1
            isSameFrame = 0;
    }

    return {
		"finding_id": finding_id,
        "source": realSource,
        "source_name": sourcename,
        "start": start,
        "end": end,
        "hasEscaping": hasEscaping,
        "hasEncodeURI": hasEncodeURI,
        "hasEncodeURIComponent": hasEncodeURIComponent,
        "value_part": sourcePart,
        "isSameFrame": isSameFrame
    };
};

window.repackSources = function (finding_id, value, sources) {
    var sourceInfo;
    var repackedSources = [];
    var oldsource = sources[0];
    var start = 0;
    var end = 0;
	var source_num_index = 0
    var x;
    if (typeof(sources) == 'string')
        sources = JSON.parse(sources);
    for (var i = 0; i < sources.length; i++) {
        var source = sources[i];

        if (source !== oldsource) {
            end = i;

            sourceInfo = getSourceInfo(finding_id, oldsource, value, start, i);
            if (parseInt(start) > -1 && parseInt(end) > -1)
                repackedSources[source_num_index] = sourceInfo;
				source_num_index += 1

            start = i;
        }

        oldsource = source;
        x = i;
    }
    sourceInfo = getSourceInfo(finding_id, oldsource, value, start, parseInt(x) + 1);

    if (parseInt(start) > -1 && parseInt(x) > -1)
        repackedSources[source_num_index] = sourceInfo;
		source_num_index += 1


    return repackedSources;
};

window.___DOMXSSFinderReport = function (sinkId, value, sources, details, loc) {
    // typically, details contains additional information about a sink. For example, sink ID 1
    // is eval-like sinks, so it would have additional information if instead Function, setTimeout, or setInterval was invoked
    // for details on sink IDs see https://github.com/cispa/persistent-clientside-xss/blob/master/src/constants/sources.py
    var detail1 = details[0];
    var detail2 = details[1];
    var detail3=loc;
    /*var finding = {
        location: window.location.href,
        domain: document.domain,
        taintedValue: value, // String - value of the (parially) tainted string
        sources: sources, // Array  - byte-wise identification of the sources that composed the string
        sinkType: sinkId, // ID - eval, innnerHTML, document.write, ...
        sinkDetails: {
            d1: detail1,
            d2: detail2,
            d3: detail3
        }, // String - Context infos how the source was called, value depends on sinkType
        stringID: 0
    };*/
	var finding_id = Math.floor(Math.random() * 10000)
	console.log('val', finding_id)
    var finding = {
		finding_id: finding_id,
        url: window.location.href,
        sources: sources, // Array  - byte-wise identification of the sources that composed the string
        sink_id: sinkId, // ID - eval, innnerHTML, document.write, ...
		d1: detail1,
		d2: detail2,
		d3: detail3,
        value: value
    };
	
    sinkTypeToName = {
        '1': 'eval',
        '2': 'document.write',
        '3': 'innerHTML',
        '5': 'script.text',
		'7': 'location',
        '8': 'script.src',
		'10': 'img.src/obj data/embed.src/iframe.src',
		'14': 'cookie',
		'15': 'postMessage',
		'16': 'set attr both',
		'17': 'set attr val',
		'20': 'localStorage name',
		'21': 'localStorage value',
		'22': 'localStorage both name',
		'23': 'localStorage both value',
		'30': 'fake eval flow'
    };

    console.log("%cTainted flow to sink " + sinkTypeToName[sinkId] + " (" + sinkId + ") found!", "font-weight: bold");
    console.log("Value: " + value);
    console.log("Code location: " + detail3);
    var buffer = "";
    var args = Array();
    var s = repackSources(finding_id, value, sources);
	finding["sources"] = s
	console.log("success")
	var prev_css = "color: black"
	var sourceNames = ""
    //for (var e in s) {
	for (var e = 0; e < s.length; e++) {
        var css = "color: black";
        if (s[e].source !== 0 && s[e].source !== 255) {
            css = "color: red";
			var a = "/" + s[e].source_name + " (" + s[e].source.toString() + ")"
			sourceNames += a
        }
		var mark = null
		if (prev_css == "color: black" && css == "color: red") {
			mark = "++"
		} else if (prev_css == "color: red" && css == "color: black") {
			mark = "--"
		} else {
			mark = ""
		}
		
		
        buffer += "%c%s";
        args.push(css);
        var text = s[e].value_part;
        if (text.indexOf("http") > -1) {
            text = text.replace("://", ":__");
            text = text.replace(".", "_")
        }
        args.push(mark + text)
		prev_css = css
    }
	console.log("Sources: " + sourceNames);
	
    args.unshift(buffer);
    console.log.apply(console, args);
   
	//download(JSON.stringify(finding), finding_id.toString() + '.txt', 'text/plain');
	
    window.postMessage(finding, "*");
    
   
};


}).toString() + ')()'; 
document.body.appendChild(sc);
////////////////////////////////////////////////////////////////////////////////////////////////
//listens for flows from the page
window.addEventListener("message", function(event){
    
  if (event.data){
   if (event.data.url){
   
    if (event.data.url == window.location.href){
        
        var flows_port = chrome.runtime.connect({name: window.location.href});
       
        flows_port.postMessage({   //send the flows to the background script
               data_type: "flows", 
               data_flows: JSON.stringify(event.data)
        });
    
    }
   }
  }
});




