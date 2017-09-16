//
//  TOTP.swift
//  Swift_OTP_POC
//
//  Created by John Moline on 8/31/17.
//  Copyright © 2017 John Moline. All rights reserved.
//

import Foundation
//import CryptoKit

class TOTP {
    
    /*//private variables
    fileprivate var DIGITS_POWER:[Int] = [ 1,10,100,1000,10000,100000,1000000,10000000,100000000 ]
    
    func toByteArray<T>(_ value: T) -> [UInt8] {
        var value = value
        return withUnsafeBytes(of: &value) { Array($0) }
    }
    
    func fromByteArray<T>(_ value: [UInt8], _: T.Type) -> T {
        return value.withUnsafeBytes {
            $0.baseAddress!.load(as: T.self)
        }
    }
    
    //this function will provide hex string to bytes array
    fileprivate func hexStr2Bytes(_ hex: String) -> [UInt8]{
        let ret:[UInt8] = Array()
        if let hexInt  = UInt(hex, radix:16) {
            //conver the int to byte array
            var bArray:[UInt8] = toByteArray(hexInt)
            //populate the bytes
            var ret:[UInt8] = [UInt8] (repeating: 0, count: bArray.count - 1)
            for i in (0 ..< ret.count) {
                ret[i] = bArray[i + 1]
            }
        }
        return ret;
    }
    
    //this function will generate the otp 
    open func generateTOTP(_ key: String, time: String, returnDigits: Int, crypto: String) -> String {
        print("Generating TOTP")
        var localKey:String = key
        var localTime: String = time
        var localReturnDigits: Int = returnDigits
        var localCrypto = crypto
        
        //check the length on the time string and append 0s if needed
        while localTime.characters.count < 16 {
            localTime = "0" + localTime;
        }
        print("Time characters processed")
        
        //create the byte array on the time and key
        var msg:[UInt8] = hexStr2Bytes(localTime)
        var k:[UInt8] = hexStr2Bytes(localKey)
        var kData:Data = Data(k)
        var msgData: Data = Data(msg)
        var hash:[UInt8] = Array.init(HMAC(key: kData, message: msgData, hashFunction: .sha1))
        print("Bit arrays and hash processed")
        
        //create the offset
        var offset:Int = Int(hash[hash.count - 1] & 0xf)
        print("Offset created")
        
        //create the binary 
        var binary:Int = Int(((hash[offset] & 0x7f) << 24) |
            ((hash[offset + 1] & 0xff) << 16) |
            ((hash[offset + 2] & 0xff) << 8) |
            (hash[offset + 3] & 0xff))
        print("Binary created")
        
        //crete the one time passcode 
        var otp: Int = binary % DIGITS_POWER[returnDigits]
        
        //process the otp and pad as needed, then return
        var result:String = String(otp)
        while result.characters.count < returnDigits {
            result = "0" + result;
        }
        print("Otp Created - " + String(otp))
        return result;
    }*/
}
