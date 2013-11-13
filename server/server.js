var express = require('express');
var commander = require('commander');

commander.version('1.0')
commander.option('-p, --port [port]', 'Port to start on.', 3000)
commander.parse(process.argv);

var app = express();

app.get('/', function(req, res) {
  res.send('OK\n');
});

app.listen(commander.port);
