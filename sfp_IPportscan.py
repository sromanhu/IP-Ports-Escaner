# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_IPportscan
# Purpose:      SpiderFoot plug-in for creating new modules.
#
# Author:      Sergio Roman Hurtado <sergio.roman87@gmail.com>
#
# Created:     15/02/2022
# Copyright:   (c) Sergio Roman Hurtado 2022
# Licence:     GPL
# -------------------------------------------------------------------------------


from spiderfoot import SpiderFootEvent, SpiderFootPlugin
import nmap

class sfp_IPportscan(SpiderFootPlugin):

    meta = {
        'name': "IP ports scan",
        'summary': "Obtiene los puertos abierto de una IP",
        'flags': [""],
        'useCases': [""],
        'categories': ["TCP_PORT_OPEN"]
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["TCP_PORT_OPEN"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        try:
            self.sf.debug(f"We use the data: {eventData}")
            print(f"We use the data: {eventData}")

            ########################
            # Insert here the code #
            ########################
            
	    #Almacena la IP introducida por el usuario en spiderfot#
            host = eventData
	
	    #Lanza la función de nmap importada de escaner de puertos#
            nmapscan = nmap.PortScanner()
	    
	    #Con la función de escanear los puertos, le pasamos los datos de la IP del usuario y el rango de puertos a escanear#
            scan = nmapscan.scan(eventData, '1000-1005')
	    
	    #Muestra por pantalla el resultado del escaneado de puertos#
            print(scan)
            ########################

            if not scan:
                self.sf.error("Unable to perform <ACTION MODULE> on " + eventData)
                return
        except Exception as e:
            self.sf.error("Unable to perform the <ACTION MODULE> on " + eventData + ": " + str(e))
            return

        evt = SpiderFootEvent(eventName, str(scan), self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_IPportscan class