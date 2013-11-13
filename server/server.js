var URL = {
  home: 'http://dimakorolev.com',
  redirect: '/r',
};

var express = require('express');
var commander = require('commander');

commander.version('1.0')
commander.option('-p, --port [port]', 'Port to start on.', 3000)
commander.option('-d, --debug', 'Enable debug endpoints.')
commander.parse(process.argv);

var app = express();

if (commander.debug) {
  app.use(express.urlencoded());
}

app.get('/', function(req, res) {
  res.send('OK\n');
});

app.post(URL.redirect, function(req, res) {
  res.writeHead(302, { 'Location': encodeURI(req.body.url || URL.home) });
  res.end();
});

if (commander.debug) {
  app.get(URL.redirect, function(req, res) {
    res.send('<form method=POST><input type=text name=url /><input type=submit /></form>\n');
  });
}

app.listen(commander.port);
