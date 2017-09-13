var exec = require('cordova/exec');

//init exports
module.exports = {
  generateotp : function(arg0, success, error) {
    console.log("Generating otp");
    exec(success, error, 'OtpGenerator', 'generateotp', [arg0]);
  }
};
