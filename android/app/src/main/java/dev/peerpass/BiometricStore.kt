package dev.peerpass

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Fingerprint unlock: K_v wrapped by a Keystore key that needs BIOMETRIC_STRONG for every
 * use and dies when fingerprints change. The wrapper is bound to the vault header
 * fingerprint; a new master password (header change) drops it.
 */
object BiometricStore {
    private const val ALIAS = "peerpass_bio"
    private fun blob(c: Context) = File(c.filesDir, "bio.bin")
    private fun fp(c: Context) = File(c.filesDir, "bio.fp")

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun key(create: Boolean): SecretKey? {
        (keyStore().getKey(ALIAS, null) as? SecretKey)?.let { return it }
        if (!create) return null
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)
                .build()
        )
        return gen.generateKey()
    }

    fun clear(c: Context) {
        blob(c).delete()
        fp(c).delete()
        runCatching { keyStore().deleteEntry(ALIAS) }
    }

    /** True if a wrapper exists for the current header; drops stale wrappers. */
    fun isEnrolled(c: Context, headerFingerprint: String): Boolean {
        if (!blob(c).exists()) return false
        if (!fp(c).exists() || fp(c).readText() != headerFingerprint) {
            clear(c)
            return false
        }
        return true
    }

    /** Cipher to authenticate with BiometricPrompt before [store]. */
    fun encryptCipher(): Cipher {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key(true))
        } catch (e: KeyPermanentlyInvalidatedException) {
            runCatching { keyStore().deleteEntry(ALIAS) }
            cipher.init(Cipher.ENCRYPT_MODE, key(true))
        }
        return cipher
    }

    fun store(c: Context, authed: Cipher, vaultKey: ByteArray, headerFingerprint: String) {
        blob(c).writeBytes(authed.iv + authed.doFinal(vaultKey))
        fp(c).writeText(headerFingerprint)
    }

    /** Cipher for BiometricPrompt, or null if the key was invalidated (new fingerprint). */
    fun decryptCipher(c: Context): Cipher? {
        val b = blob(c).takeIf { it.exists() }?.readBytes() ?: return null
        val k = key(false) ?: return null.also { clear(c) }
        return try {
            Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, k, GCMParameterSpec(128, b, 0, 12)) }
        } catch (e: KeyPermanentlyInvalidatedException) {
            clear(c)
            null
        }
    }

    fun unwrap(c: Context, authed: Cipher): ByteArray {
        val b = blob(c).readBytes()
        return authed.doFinal(b, 12, b.size - 12)
    }
}
