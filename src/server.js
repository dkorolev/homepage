var URL = {
  home: 'http://dimakorolev.com',
  redirect: '/r',
};

var _ = require('underscore');
var express = require('express');
var commander = require('commander');
var fs = require('fs');
var ejs = require('ejs');

var logger = require('./logger');

var data = require('./content/data');

var content = {
  home: ejs.render(fs.readFileSync(__dirname + '/content/home.ejs', 'utf8'), data),
};

commander.version('1.0')
commander.option('-p, --port [port]', 'Port to start on.', 3000)
commander.option('-d, --debug', 'Enable debug endpoints.')
commander.parse(process.argv);

var app = express();
app.use(logger.logger);
app.use(express.urlencoded());

app.get('/', function(req, res) {
  res.send(content.home);
});

if (commander.debug) {
  app.get('/kill', function(req, res) {
    process.exit(1);
  });
}

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
