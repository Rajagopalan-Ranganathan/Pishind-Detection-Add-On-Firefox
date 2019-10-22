/************************************************************************************
# Author:  Giovanni Armano giovanni.armano@aalto.fi
# Copyright 2015 Secure Systems Group, Aalto University, https://se-sy.org/
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
  
  TODO: error control -->tab close, -->old entries
  è veloce, controllare se non arriva a caricare la pagina prima di aver loggato tutte le richieste
  nel caso la pagina sia già stat visitata, potrebbe non scaricare contenuti essenziali per l'identificazione di siti di phishing

*************************************************************************************/

appAPI.ready(function($) {
	/** delay measurement */
	var delays = {};
	var DEBUG = false;
	log("Debug Mode");


    appAPI.resources.jQuery('1.8.0');
    //appAPI.resources.jQueryUI('1.8.22');
	appAPI.resources.includeJS('js/async.js');

	var startScript = new Date().getTime();
	delays['start'] = startScript/1000;
	log("Crossrider ready time: "+(startScript/1000));
	var partial;
	var start;
	var jspageid;
	var sentToBackground = false;
	

	/** 
	* 0 = no reponse yet
	* 1 = phish
	* 2 = not phish
	*/
	var targetResult = 0;
	var phishResult = 0;
	var targetData = "";
	var siteIdHash = "";

	/** Should i put it after document.ready?*/

	$( document ).ready(function() {
    	log( "DOM ready" );
		appAPI.message.toBackground(JSON.stringify({"tabId":appAPI.getTabId(), "message":"COLLECT"}));
	});

	/** Listen for the user decision */

	$('body').bindExtensionEvent('logDecision', function(e, data) {
		var now = new Date().getTime();
		log('decision time: ' + (now/1000));
        log(data);

        if(data.decision == "phishingContinue"){
        	appAPI.message.toBackground(JSON.stringify({"siteid":data.siteIdHash, "message":"FEEDBACK", "decision": "continue", "whitelist": data.remember, "user": true}));
        }else if(data.decision == "phishingExit"){
        	appAPI.message.toBackground(JSON.stringify({"siteid":data.siteIdHash, "message":"FEEDBACK", "decision": "exit", "google": data.remember, "user": true, "tabId": appAPI.getTabId()}));
        }

    });

	appAPI.message.addListener(function(data) {
		log("Receiving data..");
		data = JSON.parse(data);

		/** Check id the message is for the current tab */
		if(data.jspageid != null && data.jspageid == jspageid){

			siteIdHash = data.siteid;
			

			/** Result from target identification */
			if(data.target != null){
				var now = new Date().getTime();
				delays['t_i'] = now/1000;
				log('target identification time: ' + (now/1000));
				//log('Whole execution time: ' + (now - startScript));

				var otherTargets = data.otherTargets;
				log(otherTargets);

				targetResult = additionalControls(data);
				targetData = data;

				/** if the target doesn't match with the domain */
				if(targetResult == 1){
					if(phishResult == 1){
						showModal(data);
						addInformationToModal(targetData);
					}
				}
				if(targetResult == 2){
					if(phishResult == 1){
						phishResult = 2;
						showSafeModal();
        				appAPI.message.toBackground(JSON.stringify({"siteid":data.siteid, "message":"FEEDBACK", "decision": "continue", "whitelist": true, "user": false}));
					}
				}

				if(phishResult != 0){
					appAPI.message.toBackground(JSON.stringify({"message":"DELAY", "delay": delays, "phishResult": phishResult, "tabId": appAPI.getTabId()}));
				}

			}

			/** Result from phishing detection */
			if(data.phish != null){
				var now = new Date().getTime();
				delays['p_d'] = now/1000;
				log('phishing detection time: ' + (now/1000));
				//log('Whole execution time: ' + (now - startScript));
				log(data);
				/** if the target doesn't match with the domain or the result is not ready yet*/
				if(targetResult == 0 || targetResult == 1){
					if(data.phish){
						showTemporaryModal();
						phishResult = 1;
						if(targetResult == 1){
							showModal(data);
							addInformationToModal(targetData);
							appAPI.message.toBackground(JSON.stringify({"message":"DELAY", "delay": delays, "phishResult": phishResult, "tabId": appAPI.getTabId()}));
						}
					}else{
						//showSafeModal();
						phishResult = 2;
					}
				}
				if(targetResult != 0){
					appAPI.message.toBackground(JSON.stringify({"message":"DELAY", "delay": delays, "phishResult": phishResult, "tabId": appAPI.getTabId()}));
				}
			}

		}else if(data.tabId != null && data.tabId == appAPI.getTabId() && 
					data.type != null && data.type == "COLLECT"){
			main(data.data, startScript);
		}
    });


	
	function main(arrayOfItems, startScript) {
		var i;
		var now = new Date().getTime();
		delays['coll'] = now/1000;		
		log("Collecting information, time: " + (now/1000));
	    
		var sitedata = {};
		sitedata.redirections = [];
		sitedata.external_source = {};
		sitedata.loglinks = [];
		sitedata.text = "";
		sitedata.title = "";

		sitedata.access_time = appAPI.time.now();


		var tabid = appAPI.getTabId();
		var redirect = false;
		jspageid = Math.floor((Math.random() * 10000) + 1);

		log("Background collected data:" + arrayOfItems);

		if(arrayOfItems != null){ //If received data from the background
		    for (i = 0; i < arrayOfItems.length; i++) {
	        	if (arrayOfItems[i].type.localeCompare("startUrl") == 0){
	        		sitedata.redirections = [];
	        		sitedata.landurl = [];
	        		sitedata.loglinks = [];

	        		sitedata.starturl = arrayOfItems[i].requestUrl;
	        		sitedata.redirections.unshift(arrayOfItems[i].requestUrl);
	        	}else if(arrayOfItems[i].type.localeCompare("redirectUrl") == 0){
	        		if(sitedata.redirections[sitedata.redirections.length - 1] == arrayOfItems[i].requestUrl){
		        		redirect = true;
		        		sitedata.redirections.push(arrayOfItems[i].redirectUrl);
		        		sitedata.landurl = arrayOfItems[i].redirectUrl;
	        		}
	        	}else{
	        		sitedata.loglinks.push(arrayOfItems[i].requestUrl);
	        		if(arrayOfItems[i].iframeUrl){
	        			sitedata.loglinks.push(arrayOfItems[i].iframeUrl);
	        		}
	        	}
		    }
		}else{
			sitedata.starturl = location.href;
			sitedata.loglinks = getLinksFromFrames();
			log("Alternative loglinks found:");
			log(sitedata.loglinks);
		}
	    
	    /**
	    * If no redirect found set landing URL as starting URL 
	    * and remove the starting URL from the redirection chain
	    */
	    if(!redirect){
			sitedata.landurl = sitedata.starturl;
			sitedata.redirections = [];
	    }

	    /**
	    * image and input 
	    */
	    sitedata.images = document.getElementsByTagName('img').length;
	    sitedata.inputs = document.getElementsByTagName('input').length; 

	    /**
	    * sitedata.source
	    */
		sitedata.source = document.documentElement.outerHTML;

	    /**
	    * sitedata.title
	    */
	    sitedata.title = $(document).find("title").text();

	    /**
	    * sitedata.text
	    */
	    var str = getTextFromNode(document.body);
	    str = str.replace(/\s{2,}/g, ' ');
		str = str.replace(/\t/g, ' ');
		str = str.toString().trim().replace(/(\r\n|\n|\r)/g,"");
		sitedata.text = str;

		var count = -1;
		var external_source = {};
		var timer;
		var ext = '';
		var timeout = 1000; // millisec

		/**
		* Removes duplicate entry in the loglinks
		*/
		sitedata.loglinks = uniq(sitedata.loglinks);

		async.whilst(
		    function () { return count < sitedata.loglinks.length; },
		    function (callback) {
		        count++;
		        if(sitedata.loglinks[count]){

					if(validExternal(sitedata.loglinks[count])){

						timer = setTimeout(function () {
				            callback(null, count);
				        	}, timeout);
				        

						$.get(sitedata.loglinks[count], function(response) {
						    clearTimeout(timer);
						    sitedata.external_source[sitedata.loglinks[count]] = response;
						    callback(null, count);
						});
					}else{
						callback(null, count);
					}
		        }else{
		        	callback(null, count);
		        }
		        
		    },
		    function (err, n) {
		    	if(err){
		    		log(err);
		    	}
		    	if(sentToBackground){
					log("Data already sent");
		    		return;
		    	}
		    	sentToBackground = true;

		    	for (var key in sitedata.external_source) {
					sitedata.text = sitedata.text + " " + strip(sitedata.external_source[key]);
		    	}

				sitedata.jspageid = jspageid;

				now = new Date().getTime();
				delays['to_back'] = now/1000;	
				log("Send Data to toBackground, time: " + (now/1000));

				sitedata = fillEmptyData(sitedata);

				start = new Date().getTime();

				log(sitedata);

				sitedata.message = "ANALIZE";
				appAPI.message.toBackground(JSON.stringify(sitedata));
		    }
		);
	}


    /**
    * Checks if the target is the last part of host, if positive, it shouldn't be considered phish
	* 1 = phish
	* 2 = not phish
    */

    function additionalControls(data){
    	/** If solved by the target identifier
    	if(data.falsePositive != null){
    		if(data.falsePositive){
    			return 2;
    		}else{
    			return 1;
    		}
    	}*/

    	var host = appAPI.utils.getHost(location.href);
    	//var domain = appAPI.utils.getDomain(location.href);

    	log("addcontrol: "+(host.indexOf(data.target) == host.length - data.target.length));

		if(host.indexOf(data.target) == host.length - data.target.length){
			return 2;
		}

    	return 1;
    }
	

	/**
	* Checks if the link is worth to be downloaded
	*/

	function validExternal(url){
		var ext = url.split('.').pop();
        var local = url.indexOf("http://localhost");
        var addon = url.indexOf("chrome-extension://");

        if(ext== "html" || ext== "php" || ext== "htm" ||
			ext== "html#" || ext== "php#" || ext== "htm#"){

        	if(local == -1 && addon == -1){
        		return true;
        	}
        }
        return false;
	}

	/**
	* remove dublicate entry from an array
	* scr: http://stackoverflow.com/questions/9229645/remove-duplicates-from-javascript-array
	*/

	function uniq(a) {
	    var seen = {};
	    return a.filter(function(item) {
	        return seen.hasOwnProperty(item) ? false : (seen[item] = true);
	    });
	}

	/**
	* Fill the sitedata with the missing information in order to avoid problems in the 
	* python script
	*/

	function fillEmptyData(sitedata){
		var empty = false;

		if(sitedata.source === undefined){
    		sitedata.source = '';
    		empty = true;
		}
		if(sitedata.text === undefined){
    		sitedata.text = '';
    		empty = true;
		}
		if(sitedata.title === undefined){
    		sitedata.title = '';
    		empty = true;
		}
		if(sitedata.starturl === undefined){
    		sitedata.starturl = '';
    		empty = true;
		}
		if(sitedata.landurl === undefined){
    		sitedata.landurl = '';
    		empty = true;
		}

		if(empty){
			log(sitedata);
		}

    	return sitedata;
	}

	/**
	*	Append additional information at the alert modal based on the target identifier response
	*/

	function addInformationToModal(target){

		if( target.target != "unknown" && target.target != ""){
			var search;
			search = target.target;
			for (var property in target.otherTargets) {
				if(target.target != property){
					search = search + "+" + property;
				}
			}

			var html = '';

			html = htmlTargetList(target.target, target.otherTargets);

			$("#phishingInformation").after(html);
			$("#phishingButton").attr("href",'https://www.google.com/search?q='+search);

			var js = 'var targets = document.getElementsByClassName("targetClass"); for (i = 0; i < targets.length; i++) { targets[i].addEventListener("click", function(event) { if (this.href != "javascript:;") { sendData("phishingExit", false); } }); };';
			js = js + 'var href = document.getElementById("phishingButton").href; var hrefTargets = []; var i = 0; for( i = 0 ; i < 4 && document.getElementById("target-"+i) != null ; i++){ hrefTargets[i] = document.getElementById("target-"+i).href; } document.getElementById("remember").addEventListener("click", function(){ if(document.getElementById("remember").checked){ document.getElementById("phishingButton").href = "javascript:;"; document.getElementById("phishingButton").className = "phishingButtonClass"; document.getElementById("phishingButton").firstChild.style.color = "grey"; for( i = 0 ; i < 4 && document.getElementById("target-"+i) != null ; i++){ document.getElementById("target-"+i).href = "javascript:;"; document.getElementById("target-"+i).firstChild.style.textDecoration = "none"; } } else { document.getElementById("phishingButton").href = href; document.getElementById("phishingButton").disabled = false; document.getElementById("phishingButton").firstChild.style.color = "black"; document.getElementById("phishingButton").className = "phishingButtonClass phishingButtonHover"; for( i = 0 ; i < 4 && document.getElementById("target-"+i) != null ; i++){ document.getElementById("target-"+i).href = hrefTargets[i]; document.getElementById("target-"+i).firstChild.style.textDecoration = "underline"; } } });';
		
			var elem = appAPI.dom.addInlineJS({
		        js: js,
		        additionalAttributes: {charset: "UTF-8"}
		    });
		}
	}
	
	
	function castTargetWebsite(url){
		if(url == "docs.google"){
			url =  "docs.google.com"	
		}else{
			url = 'www.'+ url;
		}
		return url;
	}

	/**
	* Create the HTML in order to display the list of targets
	*/

	function htmlTargetList(target, otherTargets){
		if( target == "unknown"){
			return "";
		}
		var html = '';
		var i = 0;
		for (var property in otherTargets) {
			var url = castTargetWebsite(otherTargets[property]);
			
			if(property == target){
				html = '<p><a href="http://'+url+'" class="targetClass" id="target-'+i+'"><i class="target">'+url+'</i></a></p>' + html;
			}else{
				html = html + '<p><a href="http://'+url+'" class="targetClass" id="target-'+i+'"><i class="target">'+url+'</i></a></p>';
			}
			i++;
		}
		return '<p>This website may try to mimic:</p>' + html;
	}

	/**
	* Print the temporary message
	*/

	function showTemporaryModal(){

		appAPI.resources.includeCSS('css/style.css');


		var html = '<div id="phishingTempModal"><img id="phishingLoadImage" src="'+appAPI.resources.getImage('images/hook5gif-4.gif')+'" alt="Alert"></div>';

		$("html").append(html);
	}

	/**
	* Print the warning message
	*/

    function showModal(data){

    	if($("#phishingTempModal") != null){
	    	$("#phishingTempModal").remove();
    	}else{
	    	appAPI.resources.includeCSS('css/style.css');
    	}
    	
		var html = '';
		var js = '';
		html = ''+	
			'<div id="phishingModal">'+
				'<div id="phishingContent" style="display:none;">'+
				'<span style="position: relative;float: right;top: -30px;">Powered by  <img id="powered" src="'+appAPI.resources.getImage('images/hook5.png')+'" alt="logo"></span>'+
					'<div class="phishingBody">'+
					'<div class="bodyleft">'+
						'<img id="phishingImage" src="'+appAPI.resources.getImage('images/alert.png')+'" alt="Alert">'+
					'</div>'+
					'<div class="bodyright">'+
					'<div class="modal-header">'+
						'<h4 class="phishingTitle">Privacy threat detected</h4>'+
					'</div>'+
						'<p>We sincerely advise that you <i>do not proceed</i>.</p>'+
                		'<p>This may be a "phishing" website.</p>'+
                		'<p>It may try to illegitimately get your personal information. '+
						'<a href="https://www.phishtank.com/what_is_phishing.php?view=website" id="moreInfo" target="_blank">More Info</a>'+
						'</p>'+
					'<hr id="phishingInformation" >';

		html = html + 
					'<div style="float: left;">'+
					'<a href="https://www.google.com/search?q=" id="phishingButton" class="phishingButtonClass phishingButtonHover"><span>Close tab</span></a><br>'+
					'</div>'+
					'<div style="float: right;text-align: right; padding: 7px;">'+
						'<a href="#" id="phishingContinue">I understand the risks, but i want to proceed to this website.</a>'+
						'<br/><input type="checkbox" id="remember"><span> Do not display this message for this website in the future</span></input>'
					'</div>'+
				'</div>'+
			'</div>'+
		'</div>';

		js = js + 'document.getElementById("phishingButton").addEventListener("click", function(event){sendData("phishingExit", true);});'+
		'document.getElementById("phishingContinue").addEventListener("click", function(event){'+
						'event.preventDefault();'+
					    'var val = document.getElementById("remember").checked;'+
					    'document.getElementById("phishingModal").remove();'+
					    'sendData("phishingContinue", val);});'+
					'function sendData(origin, val){'+
					    "CrossriderAPI.fireExtensionEvent(document.body, 'logDecision', {"+
					            'decision: origin, remember: val, siteIdHash : "'+siteIdHash+'"});};';

		$("html").append(html);
		document.getElementById("phishingModal").style.backgroundColor = "rgba(0,0,0,0.8)";

		appAPI.dom.addRemoteJS({
	        url: "https://w9u6a2p6.ssl.hwcdn.net/plugins/javascripts/crossriderAPI.js",
	        additionalAttributes: {charset: "UTF-8"}
	    });
		$("#phishingContent").fadeIn( 300 );
		var elem = appAPI.dom.addInlineJS({
	        js: js,
	        additionalAttributes: {charset: "UTF-8"}
	    });
	}

	/**
	* Remove the warning message and display the "Page safe" modal that fades after 5 seconds
	*/

	function showSafeModal(){

	    appAPI.resources.includeCSS('css/style.css');
		var html = '';

	    var mode = 1;

	    if(mode == 1){
			//$("#phishingLoadImage").fadeOut( 200 , function(){$(this).attr("src", appAPI.resources.getImage('images/loading-tick.png')).fadeIn( 300 );});
			//$("#phishingTempModal").delay( 200 ).fadeOut( 300 , function(){$(this).remove();});
			
			$("#phishingTempModal").fadeOut( 200 , function(){$(this).remove();});
			
			//html = '<div id="safeModal" style="display:none;"> <div id="safeContent" ><img id="safeImage1" class="safeImage" src="'+appAPI.resources.getImage('images/hook5green.png')+'" alt="This website is safe"><img id="safeImage2" class="safeImage" src="'+appAPI.resources.getImage('images/white-tick.gif')+'" alt="This website is safe" style="display:none;"> </div></div>';
			
			html = '<div id="safeModal" style="display:none;"><img id="safeImage1" class="safeImage" src="'+appAPI.resources.getImage('images/hook5green.png')+'" alt="This website is safe"> </div></div>'

			$("body").append(html);
			$("#phishingModal").fadeOut( 300 );
			$("#phishingTempModal").fadeOut( 300 );
			$("#safeModal").delay( 500 ).fadeIn( 400 );
			//$("#safeImage2").delay( 1800 ).fadeIn( 700 );
			$("#safeModal").delay( 4000 ).fadeOut( 1500 , function(){$(this).remove();});

			$("#safeModal").hover(
			  function () {
			    $("#safeModal").stop(true, false);
			    $("#safeModal").css('opacity', '1'); 
			  },
			  function () {
			    $("#safeModal").delay( 2000 ).fadeOut( 1500 , function(){$(this).remove();});
			  }
			)
	    }else if(mode == 2){
			$("#phishingLoadImage").fadeOut( 200 , function(){$(this).attr("src", appAPI.resources.getImage('images/loading-tick.png')).fadeIn( 300 );});
			$("#phishingTempModal").delay( 700 ).fadeOut( 300 , function(){$(this).remove();});
	    }else if(mode == 3){
			html = '<div id="safeBar" style="display:none;"> <div id="safeBarContent"><img id="safaBarImage" class="safeImage" src="http://localhost/resources/images/aalto-yellow.png?r=0.422944553368529" alt="Safe"><span>Aalto university</span> </div></div>';
	    	
			$("body").append(html);
			$("#phishingModal").fadeOut( 300 );
			$("#phishingTempModal").fadeOut( 300 );

			$("#safeBar").delay( 200 ).fadeIn( 400 );
			$("#safeBar").delay( 3500 ).fadeOut( 1500 , function(){$(this).remove();});
	    }
	} 

	function goBack() {
	    window.history.back();
	}

	/**
	* Using html2canvas create a render of the page, and donwload it as png (siteId is not available as name for the png)
	* html2canvas v 4.1
	* TODO: should we try with 5? (alpha test)
	*/

	function downloadScreenShot(){

		html2canvas(document.body, {
			onrendered: function(canvas) {
				canvas.id="phishingCanvas";
				//document.body.appendChild(canvas);

				var link = document.createElement("a");
				link.download = "test.png";
				link.href = canvas.toDataURL();
				link.click();
			}
		});
	}

	/**
	* Print the sitedata
	*/

	function logSitedata(sitedata){
		log('sitedata: ' + JSON.stringify(sitedata, null, 2));
	}

	/**
	* Iterate over the child a given node in order to retrive the concatenation of the text
	*/

	function getTextFromNode(el){
		var childText;
		var extractedText;
		var words = [];
		var n;
		var a = "";
		var walk=document.createTreeWalker(el,NodeFilter.SHOW_TEXT,null,false);
		while(n=walk.nextNode()) {
			/** If script or style it shouldn't count as text */
			if(n.parentElement.tagName == "SCRIPT" || n.parentElement.tagName == "STYLE"){
				continue;
			}

			text = n.wholeText.trim();
			
			if(n.parentElement.tagName == "NOSCRIPT"){
				childText = strip(n.wholeText.trim());
				text = childText.trim();
			}

			extractedText = getTextFromString(text);
			if(extractedText.replace(/[^a-z]/gi,'') != ""){
				a = a + ' ' + extractedText;
			}
			
		}

		a = a.trim();

		return a;
	}

	/**
	* Return the source links of the page frames
	*/

	function getLinksFromFrames(){
		var frames = document.getElementsByTagName("frame");
		var links = [];
		for(var i = 0; i < frames.length ; i++){
			links.push(frames[i].src);
		}
		return links;
	}

	/**
	* Beautify and remove useless characters in a given string
	*/

	function getTextFromString(text){
		var a = "";
		var empty = text.replace(/[^a-z]/gi,'');
		/** Remove all the character in the first replace and the remove multiple spaces */
		text = text.replace(/[0-9]/gi,'');
		text = text.replace(/[\"\.\,\;\:\(\)\[\]\{\}\?\!\r?\n|\r\%\/\t]/gi,' ').replace(/ +(?= )/g,'');

		/** split the sentence in words and select only the >=2 */
		if(empty != ""){
			words = text.split(" ");
			for(var i = 0; i < words.length ;i++){
				if(words[i].length > 2){
					a = a + ' ' + words[i];
				}
			}
		}

		a = a.trim();
		/** maybe redundant */
		a = a.replace(/ +(?= )/g,'');
		return a;
	}

	/**
	* Create an iterable element in order to pass it to the the getTextFromNode
	*/

	function strip(html)
	{
	   var tmp = document.createElement("DIV");
	   tmp.innerHTML = html;
	   return getTextFromNode(tmp);
	}

	function log(string){
		if(DEBUG){
			console.log(string);
		}
	}


});