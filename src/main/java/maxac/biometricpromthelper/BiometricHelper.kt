package maxac.biometricpromthelper

import android.app.Activity
import android.content.DialogInterface
import android.content.Intent
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.support.v7.app.AlertDialog
import android.util.Base64
import android.util.Log
import java.security.*
import java.security.spec.ECGenParameterSpec

class BiometricHelper(private val activity: Activity, private val keyName: String = "keyName",
                      private val providerName: String = "AndroidKeyStore",
                      private val setupBiometricMessage: String,
                      biometricPromptDescription: String = "",
                      biometricPromptTitle: String = "Title",
                      biometricPromptSubTitle: String = "Subtitle",
                      biometricPromptSubCancel: String = "Cancel") {
    private val tag = BiometricHelper::class.java.name
    private var biometricPrompt: BiometricPrompt? = null

    init {
        biometricPrompt = BiometricPrompt.Builder(activity)
                .setDescription(biometricPromptDescription)
                .setTitle(biometricPromptTitle)
                .setSubtitle(biometricPromptSubTitle)
                .setNegativeButton(biometricPromptSubCancel,
                        activity.mainExecutor,
                        DialogInterface.OnClickListener { _, _ -> Log.d(tag, "Cancel button clicked") })
                .build()
    }

    fun registerBiometric(callback: BiometricPrompt.AuthenticationCallback): String {
        val keyPair = generateKeyPair(keyName, true, providerName)
        authenticateBiometric(callback)
        return Base64.encodeToString(keyPair.public.encoded, Base64.URL_SAFE)
    }

    fun authenticateBiometric(callback: BiometricPrompt.AuthenticationCallback) {
        if (isSupportBiometricPrompt(activity.packageManager)) {
            Log.d(tag, "Try authentication")
            val signature: Signature? = try {
                initSignature(keyName, providerName)
            } catch (e: Exception) {
                showAlertWhenNoBiometric()
                null
            }

            signature?.apply {
                Log.d(tag, "Show biometric prompt")
                biometricPrompt?.authenticate(BiometricPrompt.CryptoObject(signature), getCancellationSignal(),
                        activity.mainExecutor,
                        callback)
            }
        }
    }

    private fun showAlertWhenNoBiometric() {
        AlertDialog.Builder(activity).create().apply {
            setMessage(setupBiometricMessage)
            setButton(AlertDialog.BUTTON_NEUTRAL, "OK"
            ) { dialog, _ ->
                activity.startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
                dialog.dismiss()
            }
            show()
        }
    }

    private fun isSupportBiometricPrompt(packageManager: PackageManager): Boolean = packageManager
            .hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)

    private fun getCancellationSignal(): CancellationSignal = CancellationSignal().apply {
        this.setOnCancelListener {
            Log.d(tag, "CancellationSignal")
        }
    }

    private fun generateKeyPair(keyName: String, invalidatedByBiometricEnrollment: Boolean,
                                providerName: String): KeyPair {
        return KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, providerName).apply {
            this.initialize(
                    KeyGenParameterSpec.Builder(keyName,
                            KeyProperties.PURPOSE_SIGN)
                            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                            .setDigests(KeyProperties.DIGEST_SHA256,
                                    KeyProperties.DIGEST_SHA384,
                                    KeyProperties.DIGEST_SHA512)
                            .setUserAuthenticationRequired(true)
                            .setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment)
                            .build())
        }.generateKeyPair()
    }

    private fun initSignature(keyName: String, type: String): Signature? {
        return getKeyPair(keyName, type)?.let { keyPair ->
            Signature.getInstance("SHA256withECDSA").apply {
                initSign(keyPair.private)
            }
        }
    }

    private fun getKeyPair(keyName: String, type: String): KeyPair? {
        return KeyStore.getInstance(type).apply {
            load(null)
        }.let {
            if (it.containsAlias(keyName)) {
                val publicKey = it.getCertificate(keyName).publicKey
                val privateKey = it.getKey(keyName, null) as PrivateKey
                return KeyPair(publicKey, privateKey)
            } else null
        }
    }
}