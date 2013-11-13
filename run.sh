#!/bin/bash
if [ -r ~/node.env ] ; then
  source ~/node.env
fi
(
  cd src
  node_modules/forever/bin/forever \
    --minUptime 1000 \
    --spinSleepTime 5000 \
    node_modules/nodemon/nodemon.js --delay 2 --exitcrash server.js
)
