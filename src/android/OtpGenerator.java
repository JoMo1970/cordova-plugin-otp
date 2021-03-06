package com.otp.plugins;

import org.apache.commons.codec.binary.Base32;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaWebView;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import android.content.Context;
import android.util.Log;
import com.otp.generator.HOTP;


public class OtpGenerator extends CordovaPlugin {

  //init private class variables
  private static final String ACTION_GENERATE_OTP = "generateotp";
  private static final String TAG = "OtpGenerator";
  private JSONObject responseJSON;
  private Context context;
  private CallbackContext callback;

  @Override
  public void initialize(CordovaInterface cordova, CordovaWebView webView) {
      super.initialize(cordova, webView);
  }

  //plugin main interface function
  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
    //init response json object and context
    responseJSON = new JSONObject();
    context = this.cordova.getActivity();
    callback = callbackContext;

    try {
      Log.i(TAG, "Invoking OTP Cordova Plugin");
      //check incoming actions
      if(ACTION_GENERATE_OTP.equals(action)) {
        Log.i(TAG, "Otp Invoked");

        //get the secret key
        String secretPayload = ((JSONObject)args.get(0)).getString("secret").replace(" ", "").toUpperCase();
        Log.i(TAG, "Secret payload code retrieved - " + secretPayload);

        //get the pin size
        int pinSize = Integer.parseInt(((JSONObject)args.get(0)).getString("pinsize"));

        //process the secret payload
        String secret = (((((secretPayload.split("\\?"))[1]).split("&"))[0]).split("="))[1];
        Log.i(TAG, "Secret code processed: " + secret);

        //generate the otp
        long movingnumber = Long.valueOf(((JSONObject)args.get(0)).getString("movingnumber")).longValue();
        Log.i(TAG, "OTP Moving Number Created - " + movingnumber);
        String normalizedBase32Key = secret.replace(" ", "").toUpperCase();
        //Base32 base32 = new Base32();
        //byte[] bytes = base32.decode(normalizedBase32Key);
        String otp = HOTP.generateOTP(normalizedBase32Key, movingnumber, pinSize, false, 15);
        Log.i(TAG, "OTP Generated - " + otp);

        //send back response
        responseJSON.put("success", true);
        responseJSON.put("otp", otp);
        callback.success(responseJSON);
      }
      else {
        Log.i(TAG, "OTP command not found");
        //default action
        responseJSON.put("success", false);
        callback.error(responseJSON);
      }
    } catch(Exception e) {
        Log.e(TAG, "Exception: " + e.getMessage());

        //init response json object
        responseJSON.put("success", false);
        responseJSON.put("Error", e.getMessage());

        //send back the response with json object
        callback.error(responseJSON);
    }
    return true;
  }
}
