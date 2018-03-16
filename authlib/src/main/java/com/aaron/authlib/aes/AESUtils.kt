package com.aaron.authlib.aes

import android.support.annotation.IntDef
import android.support.annotation.StringDef
import com.aaron.authlib.BaseUtils
import com.aaron.authlib.execption.CryptException
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * @author Aaron
 * @data 2018/1/16
 */
object AESUtils {

    private const val AES = "AES"

    @IntDef(Cipher.ENCRYPT_MODE.toLong(), Cipher.DECRYPT_MODE.toLong())
    internal annotation class AESType

    const val MODE_ECB = "ECB"
    const val MODE_CBC = "CBC"
    const val MODE_CFB = "CFB"
    const val MODE_OFB = "OFB"
    const val MODE_CTR = "CTR"

    @StringDef(MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR)
    internal annotation class ModeType

    const val NO_PADDING = "NoPadding"
    const val PKCS5_PADDING = "PKCS5Padding"
    const val ISO10126_PADDING = "ISO10126Padding"

    @StringDef(NO_PADDING, PKCS5_PADDING, ISO10126_PADDING)
    internal annotation class PaddingType


    @JvmStatic
    fun encrypt(password:String, content: String,@ModeType type: String, @PaddingType paddingType: String,  ivParameter: String = ""): String {
        if(password.length != 16) {
            throw CryptException("AES password key must 128 bytes, in base java version can not support 192, 256 bytes")
        }
        val keySpec = SecretKeySpec(password.toByteArray(),AES)
        val transformation = "$AES/$type/$paddingType"
        val cipher = Cipher.getInstance(transformation)//"算法/模式/补码方式"

        if(type != MODE_ECB) {
            if(ivParameter.length != 16) {
                throw CryptException("not ECB mode must has ivParameterSpec & length must = 16 bytes in java ")
            }
            val ivParameterSpec = IvParameterSpec(ivParameter.toByteArray())
            cipher.init(Cipher.ENCRYPT_MODE, keySpec,ivParameterSpec)
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec)
        }

        val encrypted = cipher.doFinal(content.toByteArray())
        return BaseUtils.parseBytes2HexStr(encrypted)
    }

    @JvmStatic
    fun decrypt(password:String, content: String,@ModeType type: String, @PaddingType paddingType: String,  ivParameter: String = ""): String {
        if(content.length % 16 != 0) {
            throw  CryptException("Input length must be multiple of 16 when decrypting")
        }
        if(password.length != 16) {
            throw CryptException("AES password key must 128 bytes, in base java version can not support 192, 256 bytes")
        }
        val keySpec = SecretKeySpec(password.toByteArray(),AES)
        val transformation = "$AES/$type/$paddingType"
        val cipher = Cipher.getInstance(transformation)//"算法/模式/补码方式"

        if(type != MODE_ECB) {
            if(ivParameter.length != 16) {
                throw CryptException("not ECB mode must has ivParameterSpec & length must = 16 bytes in java")
            }
            val ivParameterSpec = IvParameterSpec(ivParameter.toByteArray())
            cipher.init(Cipher.DECRYPT_MODE, keySpec,ivParameterSpec)
        } else {
            cipher.init(Cipher.DECRYPT_MODE, keySpec)
        }
        val bytes: ByteArray? = BaseUtils.parseHexStr2Bytes(content)
        val encrypted = cipher.doFinal(bytes)
        return String(encrypted)
    }
}