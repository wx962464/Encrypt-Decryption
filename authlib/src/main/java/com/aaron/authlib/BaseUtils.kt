package com.aaron.authlib

object BaseUtils {

    /**
     * 二进位组转十六进制字符串
     *
     * @param buf 二进位组
     * @return 十六进制字符串
     */
    @JvmStatic
    fun parseBytes2HexStr(buf: ByteArray): String {
        val sb = StringBuilder()
        for (b: Byte in buf) {
            val temp = (b.toInt() and 0xFF)
            var hex = Integer.toHexString(temp)
            if (hex.length == 1) {
                hex = '0' + hex
            }
            sb.append(hex)
        }
        return sb.toString()
    }

    /**
     * 十六进制字符串转二进位组
     *
     * @param hexStr 十六进制字符串
     * @return 二进位组
     */
    @JvmStatic
    fun parseHexStr2Bytes(hexStr: String): ByteArray? {
        if (hexStr.isEmpty()) {
            return null
        }
        val result = ByteArray(hexStr.length / 2)

        for (i in 0 until hexStr.length / 2) {
            val high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16)
            val low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16)
            result[i] = (high * 16 + low).toByte()
        }
        return result
    }

}