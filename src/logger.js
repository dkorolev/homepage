var fs = require('fs');
var circular_json = require('circular-json');

exports.logger = function(req, res, next) {
  // TODO(dkorolev): Unify this.
  fs.appendFileSync(
    'debug.txt',
    Date.now() + circular_json.stringify(req.connection) + '\n');
  next();
};
