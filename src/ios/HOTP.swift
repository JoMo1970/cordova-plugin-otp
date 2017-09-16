//
//  HOTP.swift
//  Swift_OTP_POC
//
//  Created by John Moline on 8/31/17.
//  Copyright © 2017 John Moline. All rights reserved.
//

import Foundation
import Cryptor
import CommonCrypto

public class HOTP {
    
    //private variables
    var doubleDigits:[Int] = [0,2,4,6,8,1,3,5,7,9]
    var DIGITS_POWER:[Int] = [1,10,100,1000,10000,100000, 1000000, 10000000, 100000000]
    
    //this function will generate the otp
    func generateOTP(secret: String, movingFactor: Int64, codeDigits: Int, truncationOffset: Int) -> String {
        
        //init new byte array for text, then populate it
        var movingNumber = movingFactor
        var text = [UInt8?](repeatElement(nil, count: 8))
        for index in stride(from: text.count, to: 0, by: -1) {
            text[index] = (UInt8)(movingNumber & 0xff)
            movingNumber >>= 8
        }
        print("Counter bytes array created: " + String(describing: text))
        
        //convert the secret and text bytes array to hmac_sha1 hash
        let bytes: [UInt8] = CryptoUtils.byteArray(from: secret)
        let time : [UInt8] = CryptoUtils.byteArray(from: String(movingFactor))
        let hash:[UInt8] = (HMAC(using: HMAC.Algorithm.sha1, key: secret).update(byteArray: time)?.final())!
        
        //check offset and overwrite as needed
        var offset = hash[hash.count - 1] & 0xf
        if (0<=truncationOffset) && (truncationOffset < (hash.count - 4)) {
            offset = UInt8(truncationOffset)
        }
        
        //create binary
        var binary = ((hash[Int(offset)] & 0x7f) << 24) | ((hash[Int(offset) + 1] & 0xff) << 16) | ((hash[Int(offset) + 2] & 0xff) << 8) | (hash[Int(offset) + 3] & 0xff)
        
        //calculate the otp
        var otp = Int(binary) % DIGITS_POWER[codeDigits]
        
        //compile the string
        var result:String = String(otp)
        while result.characters.count < codeDigits {
            result = "0" + result
        }
        return result
    }

    
    /*//this function will generate the otp
    func generateOTP(secret: [UInt8], movingFactor: UInt64, codeDigits: Int, truncationOffset: Int) -> String {
        
        //init new byte array for text, then populate it
        var movingNumber = movingFactor
        var text = [UInt8?](repeatElement(nil, count: 8))
        for index in stride(from: text.count, to: 0, by: -1) {
            text[index] = (UInt8)(movingNumber & 0xff)
            movingNumber >>= 8
        }
        print("Counter bytes array created: " + String(describing: text))
        
        //convert the secret and text bytes array to hmac_sha1 hash
        //let hash = ""
        var secretData:Data = Data(fromArray:secret)
        var messageData:Data = Data(fromArray:text)
        let hash:[UInt8] = (HMAC(key: secretData, message: messageData, hashFunction: .sha1)).toArray(type: UInt8.self)
        
        //check offset and overwrite as needed
        var offset = hash[hash.count - 1] & 0xf
        if (0<=truncationOffset) && (truncationOffset < (hash.count - 4)) {
            offset = UInt8(truncationOffset)
        }
        
        //create binary
        var binary = ((hash[Int(offset)] & 0x7f) << 24) | ((hash[Int(offset) + 1] & 0xff) << 16) | ((hash[Int(offset) + 2] & 0xff) << 8) | (hash[Int(offset) + 3] & 0xff)
        
        //calculate the otp 
        var otp = Int(binary) % DIGITS_POWER[codeDigits]
        
        //compile the string 
        var result:String = String(otp)
        while result.characters.count < codeDigits {
            result = "0" + result
        }
        return result
    }*/

}


/*enum CryptoAlgorithm {
    case MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    
    var HMACAlgorithm: CCHmacAlgorithm {
        var result: Int = 0
        switch self {
        case .MD5:      result = kCCHmacAlgMD5
        case .SHA1:     result = kCCHmacAlgSHA1
        case .SHA224:   result = kCCHmacAlgSHA224
        case .SHA256:   result = kCCHmacAlgSHA256
        case .SHA384:   result = kCCHmacAlgSHA384
        case .SHA512:   result = kCCHmacAlgSHA512
        }
        return CCHmacAlgorithm(result)
    }
    
    var digestLength: Int {
        var result: Int32 = 0
        switch self {
        case .MD5:      result = CC_MD5_DIGEST_LENGTH
        case .SHA1:     result = CC_SHA1_DIGEST_LENGTH
        case .SHA224:   result = CC_SHA224_DIGEST_LENGTH
        case .SHA256:   result = CC_SHA256_DIGEST_LENGTH
        case .SHA384:   result = CC_SHA384_DIGEST_LENGTH
        case .SHA512:   result = CC_SHA512_DIGEST_LENGTH
        }
        return Int(result)
    }
}

extension String {
    
    func hmac(algorithm: CryptoAlgorithm, key: String, secret: String) -> String {
        let str = secret.cString(using: String.Encoding.utf8) //self.cString(using: String.Encoding.utf8)
        let strlen = secret.lengthOfBytes(using: String.Encoding.utf8)
        let digestLen = algorithm.digestLength
        let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
        let keyStr = key.cString(using: String.Encoding.utf8)
        let keyLen = Int(key.lengthOfBytes(using: String.Encoding.utf8))
        
        CCHmac(algorithm.HMACAlgorithm, keyStr!, keyLen, str!, strlen, result)
        
        let digest = stringFromResult(result: result, length: digestLen)
        
        result.deallocate(capacity: digestLen)
        
        return digest
    }
    
    private func stringFromResult(result: UnsafeMutablePointer<CUnsignedChar>, length: Int) -> String {
        var hash = NSMutableString()
        for i in 0..<length {
            hash.appendFormat("%02x", result[i])
        }
        return String(hash)
    }
    
}*/


//this extension will perform the conversion from data to byte array and back
extension Data {
    
    init<T>(fromArray values: [T]) {
        var values = values
        self.init(buffer: UnsafeBufferPointer(start: &values, count: values.count))
    }
    
    func toArray<T>(type: T.Type) -> [T] {
        return self.withUnsafeBytes {
            [T](UnsafeBufferPointer(start: $0, count: self.count/MemoryLayout<T>.stride))
        }
    }
}
