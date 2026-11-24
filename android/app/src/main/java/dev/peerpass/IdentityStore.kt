package dev.peerpass

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import uniffi.peerpass_ffi.generateIdentity

/**
 * The device's X25519 identity secret, encrypted with an Android Keystore AES key that
 * does NOT require user authentication, so background sync works while locked.
 */
object IdentityStore {
    private const val ALIAS = "peerpass_identity"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return gen.generateKey()
    }

    /** Returns the 32-byte secret; the caller should wipe it after use. */
    fun loadOrCreate(c: Context): ByteArray {
        val f = File(c.filesDir, "identity.bin")
        if (f.exists()) {
            val b = f.readBytes()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, b, 0, 12))
            return cipher.doFinal(b, 12, b.size - 12)
        }
        val secret = generateIdentity()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val tmp = File(c.filesDir, "identity.bin.tmp")
        tmp.writeBytes(cipher.iv + cipher.doFinal(secret))
        tmp.renameTo(f)
        return secret
    }
}
