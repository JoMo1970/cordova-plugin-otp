package com.otp.generator;

import java.io.IOException;
import java.io.File;
import java.io.ByteArrayInputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.FileInputStream ;
import java.lang.reflect.UndeclaredThrowableException;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;

import com.otp.generator.PasscodeGenerator.Signer;

public class HOTP {


	private HOTP() {}


	private static final int PIN_LENGTH = 6; // HOTP or TOTP
	private static final int REFLECTIVE_PIN_LENGTH = 9; // ROTP

	// These are used to calculate the check-sum digits.
    //                                0  1  2  3  4  5  6  7  8  9
    private static final int[] doubleDigits =
            { 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 };


    /**
     * Calculates the checksum using the credit card algorithm.
     * This algorithm has the advantage that it detects any single
     * mistyped digit and any single transposition of
     * adjacent digits.
     *
     * @param num the number to calculate the checksum for
     * @param digits number of significant places in the number
     *
     * @return the checksum of num
     */
    public static int calcChecksum(long num, int digits) {
        boolean doubleDigit = true;
        int     total = 0;
        while (0 < digits--) {
            int digit = (int) (num % 10);
            num /= 10;
            if (doubleDigit) {
                digit = doubleDigits[digit];
            }
            total += digit;
            doubleDigit = !doubleDigit;
        }
        int result = total % 10;
        if (result > 0) {
            result = 10 - result;
        }
        return result;
    }

    /**
     * This method uses the JCE to provide the HMAC-SHA-1
     * algorithm.
     * HMAC computes a Hashed Message Authentication Code and
     * in this case SHA1 is the hash algorithm used.
     *
     * @param keyBytes   the bytes to use for the HMAC-SHA-1 key
     * @param text       the message or text to be authenticated.
     *
     * @throws NoSuchAlgorithmException if no provider makes
     *       either HmacSHA1 or HMAC-SHA-1
     *       digest algorithms available.
     * @throws InvalidKeyException
     *       The secret provided was not a valid HMAC-SHA-1 key.
     *
     */

    public static byte[] hmac_sha1(byte[] keyBytes, byte[] text)
            throws NoSuchAlgorithmException, InvalidKeyException
    {
        Mac hmacSha1;
        try {
            hmacSha1 = Mac.getInstance("HmacSHA1");
        } catch (NoSuchAlgorithmException nsae) {
            hmacSha1 = Mac.getInstance("HMAC-SHA-1");
        }
        SecretKeySpec macKey =
                new SecretKeySpec(keyBytes, "RAW");
        hmacSha1.init(macKey);
        return hmacSha1.doFinal(text);
    }

    private static final int[] DIGITS_POWER
            // 0 1  2   3    4     5      6       7        8
            = {1,10,100,1000,10000,100000,1000000,10000000,100000000};

    /**
     * This method generates an OTP value for the given
     * set of parameters.
     *
     * @param secret       the shared secret
     * @param movingFactor the counter, time, or other value that
     *                     changes on a per use basis.
     * @param codeDigits   the number of digits in the OTP, not
     *                     including the checksum, if any.
     * @param addChecksum  a flag that indicates if a checksum digit
     *                     should be appended to the OTP.
     * @param truncationOffset the offset into the MAC result to
     *                     begin truncation.  If this value is out of
     *                     the range of 0 ... 15, then dynamic
     *                     truncation  will be used.
     *                     Dynamic truncation is when the last 4
     *                     bits of the last byte of the MAC are
     *                     used to determine the start offset.
     * @throws NoSuchAlgorithmException if no provider makes
     *                     either HmacSHA1 or HMAC-SHA-1
     *                     digest algorithms available.
     * @throws InvalidKeyException
     *                     The secret provided was not
     *                     a valid HMAC-SHA-1 key.
     *
     * @return A numeric String in base 10 that includes
     * {@link codeDigits} digits plus the optional checksum
     * digit if requested.
     */
    static public String generateOTP(String secret,
                                     long movingFactor,
                                     int codeDigits,
                                     boolean addChecksum,
                                     int truncationOffset)
            throws NoSuchAlgorithmException, InvalidKeyException
    {
        // put movingFactor value into text byte array
        String result = null;
        int digits = addChecksum ? (codeDigits + 1) : codeDigits;
        byte[] text = new byte[8];
        for (int i = text.length - 1; i >= 0; i--) {
            text[i] = (byte) (movingFactor & 0xff);
            movingFactor >>= 8;
        }
        //System.out.println("HOTP"+" counter bytes array created - " + text.toString());

        // compute hmac hash
		byte[] tmpSecret = decodeKey(secret);
        byte[] hash = hmac_sha1(tmpSecret, text);
        //System.out.println("HOTP"+" Hash created - " + hash.toString());

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;
//        if ( (0<=truncationOffset) &&
//                (truncationOffset<(hash.length-4)) ) {
//            offset = truncationOffset;
//        }
        //System.out.println("HOTP"+" counter bytes array created - " + text.toString());
        int binary = hashToInt(hash, offset) & 0x7FFFFFFF;
//        int binary1 =
//                ((hash[offset] & 0x7f) << 24)
//                        | ((hash[offset + 1] & 0xff) << 16)
//                        | ((hash[offset + 2] & 0xff) << 8)
//                        | (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];
        if (addChecksum) {
            otp =  (otp * 10) + calcChecksum(otp, codeDigits);
        }
        result = Integer.toString(otp);
        while (result.length() < digits) {
            result = "0" + result;
        }
        return result;
    }

    private static int hashToInt(byte[] bytes, int start) {
        DataInput input = new DataInputStream(
            new ByteArrayInputStream(bytes, start, bytes.length - start));
        int val;
        try {
          val = input.readInt();
        } catch (IOException e) {
          throw new IllegalStateException(e);
        }
        return val;
      }


    private static byte[] decodeKey(String secret) {
		Base32 tmpEncoder = new Base32();
		return tmpEncoder.decode(secret);
      }

    static Signer getSigningOracle(String secret) {
        try {
          byte[] keyBytes = decodeKey(secret);
          final Mac mac = Mac.getInstance("HMACSHA1");
          mac.init(new SecretKeySpec(keyBytes, ""));

          // Create a signer object out of the standard Java MAC implementation.
          return new Signer() {
            @Override
            public byte[] sign(byte[] data) {
              return mac.doFinal(data);
            }
          };
        } catch (Exception error) {
        	System.out.println(error.getMessage());
        }

        return null;
      }

    private static String computePin(String secret, long otp_state, byte[] challenge)
    	      throws Exception {
    	    if (secret == null || secret.length() == 0) {
    	      throw new Exception("Null or empty secret");
    	    }

    	    try {
    	      Signer signer = getSigningOracle(secret);
    	      PasscodeGenerator pcg = new PasscodeGenerator(signer,
    	        (challenge == null) ? PIN_LENGTH : REFLECTIVE_PIN_LENGTH);

    	      return (challenge == null) ?
    	             pcg.generateResponseCode(otp_state) :
    	             pcg.generateResponseCode(otp_state, challenge);
    	    } catch (GeneralSecurityException e) {
    	      throw new Exception("Crypto failure", e);
    	    }
    	  }

	public static void main(String[] args) {
        System.out.println("HOTP"+" Start Process");

        boolean newKey=false;
        String lastPin="151641";
        String secret = "";
        //secret = "IFLECNJQGZFVEMZV"; //jq215m - last good 15
        secret = "GBMFONSCI5IFUQZZ"; //rh267n  - Last Good is 696420
        //secret = "KUYUMUZQINHFQVZU"; //rh267a  - Last Good is 151641
        long movingFactor=0;

        //generateOTP
        int codeDigits=PIN_LENGTH;
        boolean addChecksum=false; //Should be False
        int truncationOffset=4;    //Code Commented Out

        //computePin
 	    byte[] challenge = null;

        System.out.println("HOTP"+" secret(Base32) = "+secret);

        try {
        	if (!newKey) {
		          for (long xx=1;xx<=1000;xx++) {
		        	  movingFactor = xx;
		        	  String otpPin = generateOTP(secret, movingFactor, codeDigits, addChecksum, truncationOffset);
		        	  String otpPin1 = computePin(secret, movingFactor, challenge);
		        	  if (otpPin.equals(lastPin)) {
		       	        System.out.println("HOTP"+" "+movingFactor+" OTP = "+otpPin);
		       	        System.out.println("computePin"+" "+movingFactor+" OTP = "+otpPin1);
		       	        break;
		        	  }
		          }
 	    	      movingFactor = movingFactor+1;
          } else
    	      if (newKey)
    	    	  movingFactor = 1;
 	        System.out.println("Next Pin is "+" "+movingFactor+" OTP = "+generateOTP(secret, movingFactor, codeDigits, addChecksum, truncationOffset));
   	        System.out.println("Next computePin is "+" "+movingFactor+" OTP = "+computePin(secret, movingFactor, challenge));

        } catch (Exception e) {
        	System.out.println("HOTP"+" "+e.getStackTrace());
        }

        System.out.println("HOTP"+" End Process");
	}

}
