import Foundation
import Base32
import OneTimePassword


@objc(OtpGenerator) class OtpGenerator : CDVPlugin {

   //this function will validate if a certificate is installed within the app file structure or in the keychain of the device
   @objc(generateotp:)
   func generateotp(_ command: CDVInvokedUrlCommand) {

    //get the secret key
    let secretPayload = ((command.argument(at: 0) as! [String:Any])["secret"] as! String).replacingOccurrences(of: " ", with: "").uppercased()
    print("Secret payload received: " + secretPayload)

    //grab the digits count
    let pinsize: Int = (command.argument(at: 0) as! [String:Any])["pinsize"] as! Int
    print("Pin Size received: " + "\(pinsize)")

    //grab the moving number
    let movingnumber: Int = (command.argument(at: 0) as! [String:Any])["movingnumber"] as! Int
    print("Moving Number received: " + "\(movingnumber)")

    //parse out the secret string
    let secret:String = (((((secretPayload.components(separatedBy: "?") as [String])[1] as String).components(separatedBy: "&") as [String])[0] as String).components(separatedBy: "=") as [String])[1] as String
    print("Secret key processed: " + secret)

    //convert the incoming secret code to base32 data
    let secretData = MF_Base32Codec.data(fromBase32String: secret)

    //get the system time
    //var time = ((Date().timeIntervalSince1970 / 1000) / 30)
    //print("Time variable created: " + String(time))

    //init otp generator and otp
    let generator = Generator(factor: .counter(UInt64(movingnumber)), secret: secretData!, algorithm: .sha1, digits: pinsize)
    let otp = Token(generator: generator!)

     //init plugin result
    let response: Dictionary = ["success" : true, "otp" : otp.currentPassword] as [String : Any]
     let pluginResult = CDVPluginResult(
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
