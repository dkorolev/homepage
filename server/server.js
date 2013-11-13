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
app.use(express.urlencoded());

app.get('/', function(req, res) {
  res.send('OK\n');
});

app.post(URL.redirect, function(req, res) {
  res.writeHead(302, { 'Location': encodeURI(req.body.url || URL.home) });
  res.end();
});

app.get(URL.redirect, function(req, res) {
  if (req.query.url) {
    res.writeHead(302, { 'Location': encodeURI(req.query.url || URL.home) });
    res.end();
  } else {
    if (commander.debug) {
      res.send('<form method=GET><input type=text name=url /><input type=submit /></form>\n');
    } else {
      res.writeHead(400);
      res.end();
    }
  }
});

app.listen(commander.port);
