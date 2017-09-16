import Foundation
import Base32
import OneTimePassword


@objc(OtpGenerator) class OtpGenerator : CDVPlugin {

   //this function will validate if a certificate is installed within the app file structure or in the keychain of the device
   @objc(generateotp:)
   func generateotp(_ command: CDVInvokedUrlCommand) {
    //get the secret key 
    var secretPayload = ((command.argument(at: 0) as! [String:Any])["secret"] as! String).replacingOccurrences(of: " ", with: "").uppercased()
    print("Secret payload received: " + secretPayload)
    
    //parse out the secret string
    let secret:String = (((((secretPayload.components(separatedBy: "?") as [String])[1] as String).components(separatedBy: "&") as [String])[0] as String).components(separatedBy: "=") as [String])[1] as String
    print("Secret key processed: " + secret)
    
    //convert the incoming secret code to base32 data 
    let secretData = MF_Base32Codec.data(fromBase32String: secret)
    
    //get the system time
    var time = ((Date().timeIntervalSince1970 / 1000) / 30)
    print("Time variable created: " + String(time))
    
    //init otp generator and otp
    let generator = Generator(factor: .counter(UInt64(time)), secret: secretData!, algorithm: .sha1, digits: 6)
    let otp = Token(generator: generator!)
    
    
    /*//break up the string to extract the secret key
    let secret:String = (((((secretPayload.components(separatedBy: "?") as [String])[1] as String).components(separatedBy: "&") as [String])[0] as String).components(separatedBy: "=") as [String])[1] as String
    print("Secret key processed: " + secret)
    
    //get the system time 
    var time = ((Date().timeIntervalSince1970 / 1000) / 30)
    print("Time variable created: " + String(time))
    
    //generate the otp
    var hotp:HOTP = HOTP()
    var otp:String = hotp.generateOTP(secret: secret, movingFactor: Int64(time), codeDigits: 6, truncationOffset: 15)
    print("Otp created: " + otp)*/
    
    
     //init plugin result
    var response: Dictionary = ["success" : true, "otp" : otp.currentPassword] as [String : Any]
     var pluginResult = CDVPluginResult(
         status: CDVCommandStatus_OK,
         messageAs: response
     )

     //send the callback object back
     print("Sending back cordova response")
     self.commandDelegate!.send(
       pluginResult,
       callbackId: command.callbackId
     )
   }
}
