var URL = {
  home: 'http://dimakorolev.com',
  redirect: '/r',
};

var ENV = {
  LOG: 'DKOROLEV_LOG_DIR',
};

var commander = require('commander');
var ejs = require('ejs');
var express = require('express');
var fs = require('fs');
var path = require('path');
var _ = require('underscore');

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
var log_dir = process.env[ENV.LOG];
if (log_dir) {
  app.use(logger.createLogger(log_dir));
} else {
  console.log('For full logging please set the ' + ENV.LOG + ' environmental variable.');
}
app.use(express.urlencoded());
app.use(express.compress());
console.log(path.join(__dirname, 'content/static'));
app.use('/static', express.static(path.join(__dirname, 'content/static')));

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
