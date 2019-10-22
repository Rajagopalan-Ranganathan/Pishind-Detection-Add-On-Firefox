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
*************************************************************************************/

appAPI.ready(function($) {
	//appAPI.browserAction.setResourceIcon('images/aalto-yellow.png');
	appAPI.browserAction.setTitle('');
	
	var privacy = 0;
	
	appAPI.contextMenu.add("key1", "Enable metadata collection", function (data) {
		if(privacy === 0){
			appAPI.contextMenu.updateTitle("key1", "Disable metadata collection");
			privacy = 1;
		}else if(privacy === 1){
			appAPI.contextMenu.updateTitle("key1", "Enable metadata collection");
			privacy = 0;
		}else if(privacy === 2){
			appAPI.contextMenu.updateTitle("key1", "Enable metadata collection");
			appAPI.contextMenu.updateTitle("key2", "Enable website collection");
			privacy = 0;
		}
		checkConnection(0, JSON.stringify({"privacy":privacy}));
	}, ["all"]);
	
	appAPI.contextMenu.add("key2", "Enable website data collection", function (data) {
		if(privacy === 0){
			appAPI.contextMenu.updateTitle("key1", "Disable metadata collection");
			appAPI.contextMenu.updateTitle("key2", "Disable website data collection");
			privacy = 2;
		}else if (privacy === 1){
			appAPI.contextMenu.updateTitle("key2", "Disable website collection");
			privacy = 2;
		}else if(privacy === 2){
			appAPI.contextMenu.updateTitle("key2", "Enable website collection");
			privacy = 1;
		}
		checkConnection(0, JSON.stringify({"privacy":privacy}));
	}, ["all"]);
	
	/** Inizialization of the environment, remove entry from the db */
	var i=0;
	var phishingDb = [];
	var tabStatus = [];

	/** ---------------- web socket ----------------  */
	/**
	* In order to open only a single socket that remain open
	* we use it on the background js, check if the connection is secure and then
	* wait for the extension.js send us the data for the server, then we renpond with the ws
	* in order to allow the foreground task to handle the response
	*/
	var port = 9000;
	var ws;	
	var attempt = 3;

	//openSocket();

	function openSocket(){
		
		console.log("Phishing detecting socket open:");

		if (window.location.protocol == "https:"){
			ulrWs = "wss://localhost:"+port;
		}else{
			ulrWs = "ws://localhost:"+port;
		}

		var tmp = new WebSocket(ulrWs);
		ws = tmp;

		/**
		* When the socket is open send a auth message
		* TODO: add token?
		*/
		ws.onopen = function()
		{
			ws.send(JSON.stringify({'auth':true}));
		};

		/**
		* When receive a message, the result is forwarded to all the tabs
		* TODO: should be implemented in a way that only the tab that request the
		* check receives the answer
		*/
		ws.onmessage = function (evt) 
		{ 
			var received_msg = JSON.parse(evt.data);
			if(received_msg.privacy != null){
			
				privacy = received_msg.privacy;
				if(received_msg.privacy == 0){
					appAPI.contextMenu.updateTitle("key1", "Enable metadata collection");
					appAPI.contextMenu.updateTitle("key2", "Enable website data collection");
				}else if(received_msg.privacy == 1){
					appAPI.contextMenu.updateTitle("key1", "Disable metadata collection");
					appAPI.contextMenu.updateTitle("key2", "Enable website data collection");
				}else if(received_msg.privacy == 2){
					appAPI.contextMenu.updateTitle("key1", "Disable metadata collection");
					appAPI.contextMenu.updateTitle("key2", "Disable website data collection");
				}
			}else{
				appAPI.message.toAllTabs(evt.data);
			}
		};

		/**
		* Handle the close of the websocket
		*/
		ws.onclose = function()
		{ 
			// websocket is closed.
			//("Connection is closed.."); 
		};

		ws.onerror = function()
		{ 
			//("Error occur.."); 
			appAPI.message.toAllTabs(evt.data);
		};

		if(ws.readyState == WebSocket.OPEN){
			//("Open"); 
			return true;
		}else{
			//("Not open"); 
			return false;
		}
	}

	/** ---------------- COLLECTING DATA ----------------  */
	/**
	* Receive the site data from extension.js and send it to the server
	*/
	appAPI.message.addListener(function(command) {
		data = JSON.parse(command);

		if(data.message == "FEEDBACK"){
			if(data.decision ==  "exit" &&  data.google == true){
				appAPI.tabs.closeTab(data.tabId);
			}
		}

		if(data.message == "DELAY"){
			tabStatus[data.tabId] = data.phishResult;
			changeIcon(data.tabId);
		}


		if(data.message == "ANALIZE" || data.message == "FEEDBACK" || data.message == "DELAY"){
			checkConnection(0, command);		
		}else if (data.message == "COLLECT"){
			collectFromDb(data);
		}
	});	

	/**
	* Fetch the data from the array and send the information of the tab to the foreground
	*/

	function collectFromDb(data){
		var message = {
			"tabId": data.tabId,
			"type": "COLLECT"
		};
		if(data.tabId != null && phishingDb[data.tabId] != null && phishingDb[data.tabId].length > 0){
			message.data = phishingDb[data.tabId];
			appAPI.message.toAllTabs(JSON.stringify(message));
			phishingDb[data.tabId] = null;
		}else{
			message.data = null;
			appAPI.message.toAllTabs(JSON.stringify(message));
		}
	}

	/**
	* Look for the state of the socket and try to open it if it's close
	*/

    function checkConnection(count, sitedata){
    	if(ws != undefined && ws.readyState == WebSocket.CONNECTING){
    		setTimeout(checkConnection, 300, count, sitedata);
    		return;
    	}
    	
    	if(ws != undefined && ws.readyState == WebSocket.OPEN){
    		sendToServer(sitedata);
    		return;
    	}

    	if(count < attempt){
			//("Socket close, wait for it..");
			if(openSocket()){
				sendToServer(sitedata);
			}else{
				setTimeout(checkConnection, 300, ++count, sitedata);
			}
			//checkConnection(++count, sitedata);
		}else{
			//("Cannot send data through a close connection");
		}
    }

	/**
	* Send the data through the websocket
	* TODO: handle the case of server not connected
	*/
	function sendToServer(sitedata){
		//Sending data to the server..
		ws.send(sitedata);
	}



	/** ---------------- COLLECTING DATA ----------------  */
	/** ---------------- save the starting url ----------------  */
	appAPI.webRequest.monitor.onBeforeNavigate.addListener({
        callback: function(item) {

        	phishingDb[item.tabId] = [];
        	phishingDb[item.tabId].push({
					"type"	: 			"startUrl",
					"requestUrl": 		item.requestUrl
				});
        }
    });

    /** ---------------- save all the requests done by the page ----------------  */
    /** TODO: Check how to insert in the json the information of the iframe */
    appAPI.webRequest.monitor.onRequest.addListener({
	    callback: function(item) {
	    	if(item.iframeUrl){
	    		phishingDb[item.tabId].push({
					"type"	: 			"requestUrl",
					"requestUrl": 		item.iframeUrl
					});
	    	}
	    	if(item.requestUrl){
	    		phishingDb[item.tabId].push({
					"type"	: 			"requestUrl",
					"requestUrl": 		item.requestUrl
					});
    		}
	    }
	});
	
	/** ---------------- save the redirects ----------------  */
	appAPI.webRequest.monitor.onRedirect.addListener({
	    callback: function(item) {
    		phishingDb[item.tabId].push({
				"type"	: 			"redirectUrl",
				"redirectUrl": 		item.redirectUrl,
				"requestUrl": 		item.requestUrl
				});
	    }
	});

	/** 
	* Icon status management
	*/



	function changeIcon(tabId){
		if(tabStatus[tabId] == undefined || tabStatus[tabId] == null ){
        	appAPI.browserAction.removeBadge();
			//appAPI.browserAction.setResourceIcon('images/aalto-yellow.png');
			appAPI.browserAction.setTitle('');
        	return;
		}

		if(tabStatus[tabId] == 1){
		    appAPI.tabs.getActive(function(tabInfo) {
		        if(tabId == tabInfo.tabId){
					//appAPI.browserAction.setResourceIcon('images/aalto-unsafe.gif');
					appAPI.browserAction.setTitle('This website is unsafe');
					appAPI.browserAction.setBadgeText(' ', [255,0,0,255]);
		        }
		    });
			
		}else{
		    appAPI.tabs.getActive(function(tabInfo) {
		        if(tabId == tabInfo.tabId){
					//appAPI.browserAction.setResourceIcon('images/aalto-safe.gif');
					appAPI.browserAction.setTitle('This website is safe');
					appAPI.browserAction.setBadgeText(' ', [0,255,0,255]);
		        }
		    });
		}
	}

    appAPI.tabs.onTabSelectionChanged(function(tabInfo) {
    	changeIcon(tabInfo.tabId);
    });

});
