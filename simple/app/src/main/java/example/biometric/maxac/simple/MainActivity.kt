package example.biometric.maxac.simple

import android.hardware.biometrics.BiometricPrompt
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.util.Base64
import android.widget.Toast
import kotlinx.android.synthetic.main.activity_main.*
import maxac.biometricpromthelper.BiometricHelper
import java.security.Signature
import java.security.SignatureException

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        var publicKey = ""
        var signature : Signature

        val biometricHelper = BiometricHelper(this, "testKeyName", "AndroidKeyStore",
                "no Biometric, please setup!")

        registerBiometric.setOnClickListener {
            publicKey = biometricHelper.registerBiometric(object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Toast.makeText(applicationContext, "AuthenticationError: $errString", Toast.LENGTH_SHORT).show()
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    // send publicKey to server
                    Toast.makeText(applicationContext, publicKey, Toast.LENGTH_SHORT).show()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(applicationContext, "onAuthenticationFailed", Toast.LENGTH_SHORT).show()
                }
            })
        }

        authenticateBiometric.setOnClickListener {
            biometricHelper.authenticateBiometric(object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Toast.makeText(applicationContext, "AuthenticationError: $errString", Toast.LENGTH_SHORT).show()
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    signature = result.cryptoObject.signature
                    try {
                        // sign string with private key
                        signature.update("Data that we send to server".toByteArray())
                        val signatureString = Base64.encodeToString(signature.sign(), Base64.URL_SAFE)
                        // signatureString send to the server and then verified with already sent publicKey
                        // from registration
                        // https://android-developers.googleblog.com/2015/10/new-in-android-samples-authenticating.html
                        Toast.makeText(applicationContext, signatureString, Toast.LENGTH_SHORT).show()
                    } catch (e: SignatureException) {
                        throw RuntimeException()
                    }
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(applicationContext, "onAuthenticationFailed", Toast.LENGTH_SHORT).show()
                }
            })
        }
    }
}
