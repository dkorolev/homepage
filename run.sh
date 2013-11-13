#!/bin/bash
# TODO(dkorolev): 'nodemon' seems to not be able to pass command line parameters. Perhaps fix one day.
(cd src; npm install)
(cd src; ./node_modules/forever/bin/forever start node_modules/nodemon/nodemon.js --delay 2 server.js)
