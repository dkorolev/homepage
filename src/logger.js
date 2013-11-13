var fs = require('fs');
var path = require('path');
var dateformat = require('dateformat');
var circular_json = require('circular-json');

exports.createLogger = function(dir) {
  return function(req, res, next) {
    var now = Date.now();
    fs.appendFileSync(
      path.join(dir, dateformat(now, 'yyyy-mm-dd-HH') + '.txt'),
      now + ':' + circular_json.stringify(req.connection) + '\n');
    next();
  };
};
