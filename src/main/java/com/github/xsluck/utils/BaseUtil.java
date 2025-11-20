package com.github.xsluck.utils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class BaseUtil {

	/**
	 * byte[]转十六进制字符串
	 * string.这里我们可以将byte转换成int，然后利用Integer.toHexString(int)来转换成16进制字符串。
	 *
	 * @param src 原数组
	 * @return
	 */
	public static String bytesToHexString(byte[] src) {
		StringBuilder stringBuilder = new StringBuilder("");
		if (src == null || src.length <= 0) {
			return null;
		}
		for (int i = 0; i < src.length; i++) {
			int v = src[i] & 0xFF;
			String hv = Integer.toHexString(v);
			if (hv.length() < 2) {
				stringBuilder.append(0);
			}
			stringBuilder.append(hv);
		}
		return stringBuilder.toString().toUpperCase(Locale.getDefault());
	}

	public static String paddingDecryptDataToString(String data) {
		byte[] bytes = BaseUtil.hexStringToBytes(data);
		for (int i = 1; i < bytes.length; i++) {
			if (bytes[i - 1] == 125 && bytes[i] == -128) {
				return BaseUtil.bytesToHexString(Arrays.copyOfRange(bytes, 0, i));
			}
		}
		return data;
	}

	/**
	 * byte[]转十六进制字符串
	 * string.这里我们可以将byte转换成int，然后利用Integer.toHexString(int)来转换成16进制字符串。
	 *
	 * @param src 原数组
	 * @return
	 */
	public static String byteToHexString(byte src) {
		int v = src & 0xFF;
		String hv = Integer.toHexString(v);
		if (hv.length() < 2) {
			hv = hv + "0";
		}
		return hv;
	}

	public static String bytesToHexString(byte[] src, int endInx) {
		StringBuilder stringBuilder = new StringBuilder("");
		if (src == null || src.length <= 0) {
			return null;
		}
		for (int i = 0; i < endInx; i++) {
			int v = src[i] & 0xFF;
			String hv = Integer.toHexString(v);
			if (hv.length() < 2) {
				stringBuilder.append(0);
			}
			stringBuilder.append(hv);
		}
		return stringBuilder.toString();
	}

	/**
	 * 十六进制转十进制整形
	 *
	 * @param hexString
	 * @return
	 */
	public static long hexToTen(String hexString) {
		return new BigInteger(hexString, 16).longValue();
	}

	/**
	 * int转十六进制的字符串
	 *
	 * @param value 整形
	 * @param len   返回字符串的长度
	 * @return
	 */
	public static String intToHexString(int value, int len) {
		String str = "00000000000000000000000000000000";// 32位
		String hexString = Integer.toHexString(value);
		if (hexString.length() >= len) {
			hexString = hexString.substring(0, len);
		} else {
			hexString = str.substring(0, len - hexString.length()) + hexString;
		}
		return hexString;
	}

	/**
	 * 十六进制字符串转byte[]
	 *
	 * @param hexString 十六进制数
	 * @return
	 */
	public static byte[] hexStringToBytes(String hexString) {
		if (hexString == null || hexString.equals("")) {
			return null;
		}
		if (hexString.length() % 2 == 1) {
			hexString = "0" + hexString;
		}
		hexString = hexString.toLowerCase();
		int length = (hexString.length() + 1) / 2;
		char[] hexChars = hexString.toCharArray();
		byte[] d = new byte[length];
		for (int i = 0; i < length; i++) {
			int pos = i * 2;
			d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
		}
		return d;
	}

	/**
	 * char转byep
	 *
	 * @param c 字符
	 * @return
	 */
	private static byte charToByte(char c) {
		return (byte) "0123456789abcdef".indexOf(c);
	}

	public static int byteArrayToInt(byte[] res, int offset, boolean netByteSequence) {
		if (netByteSequence) {// 网络字节顺序(高位在前)
			int targets = (res[offset + 3] & 0xff) | ((res[offset + 2] << 8) & 0xff00) | ((res[offset + 1] << 24) >>> 8)
					| (res[offset] << 24);
			return targets;
		} else {// 非网络字节顺序(低位在前)
			int targets = (res[offset] & 0xff) | ((res[offset + 1] << 8) & 0xff00) | ((res[offset + 2] << 24) >>> 8)
					| (res[offset + 3] << 24);
			return targets;
		}
	}

	public static String doubleToString(double src, int dotLen) {
		String s = String.valueOf(src);
		int inx = s.lastIndexOf(".");
		String zeros = "00000000000000000000";
		if (inx == -1) {
			return s + "." + zeros.substring(0, dotLen);
		} else if (s.length() - 1 - inx >= dotLen) {
			return s.substring(0, inx + dotLen + 1);
		} else {
			return s + zeros.substring(0, dotLen - (s.length() - 1 - inx));
		}
	}

	/**
	 * 字符串转int
	 *
	 * @param s        字符串
	 * @param defValue 缺省值
	 * @return 转换结果
	 */
	public static int strToInt(String s, int defValue) {
		s = s.trim();
		if (s.length() == 0)
			return defValue;
		try {
			return Integer.parseInt(s);
		} catch (Exception e) {
			return defValue;
		}
	}

	public static boolean isMoney(String moneyString) {
		boolean result = false;
		if (moneyString.equals("")) {
			return false;
		}
		double temp = 0;
		try {
			temp = Double.valueOf(moneyString);
			result = true;
		} catch (Exception e) {
			result = false;
		}
		if (result) {
			moneyString = String.valueOf(temp);
			if (moneyString.indexOf(".") != -1 && moneyString.length() - 1 - moneyString.indexOf(".") > 2) {
				result = false;
			}
		}
		return result;
	}

	public static String fenToYuanStr(String src) {
		StringBuffer temp = new StringBuffer("");
		if (src.length() <= 2) {
			temp.append(Double.valueOf(src) / 100.0);
		} else {
			temp.append(src.substring(0, src.length() - 2));
			temp.append(".");
			temp.append(src.substring(src.length() - 2, src.length()));
		}

		return temp.toString();
	}

	/**
	 * 转为unix时间
	 *
	 * @param hexStr 16进制的字符串
	 * @return
	 */
	public static Date String2UnixDate(String hexStr) {
		long timePoke = hexToTen(hexStr) * 1000l;
		Date date = new Date(timePoke);
		return date;
	}

	/**
	 * 将i转换为两位数：例如 1转为01,11转为11
	 *
	 * @param i
	 * @return
	 */
	public static String numberTo01Format(int i) {
		return String.format("%02d", i);
	}

	/**
	 * 二进制转为十进制
	 *
	 * @param binary
	 * @return
	 */
	public static int toTenFromBinaryString(String binary) {
		return Integer.parseInt(Integer.valueOf(binary, 2).toString());
	}

	/**
	 * 把数组所有元素排序，并按照“参数=参数值”的模式用“&”字符拼接成字符串
	 *
	 * @param params 需要排序并参与字符拼接的参数组
	 * @return 拼接后字符串
	 */
	public static String createLinkString(Map<String, Object> params) {
		List<String> keys = new ArrayList<String>(params.keySet());
		Collections.sort(keys);
		StringBuffer preStr = new StringBuffer("");
		for (int i = 0; i < keys.size(); i++) {
			String key = keys.get(i);
			if (params.get(key) != null) {
				String value = params.get(key).toString();
				preStr.append(key).append("=").append(value).append("&");
			}
		}
		return preStr.toString().substring(0, preStr.length() - 1);
	}

	/**
	 * 字节数组链接
	 * 
	 * @param totalLen
	 * @param bytes
	 * @return
	 */
	public static byte[] arrayApend(int totalLen, byte[]... bytes) {
		byte[] tempByte = new byte[totalLen];
		int destPos = 0;
		for (int length = 0; length < bytes.length; length++) {
			System.arraycopy(bytes[length], 0, tempByte, destPos, bytes[length].length);
			destPos += bytes[length].length;
		}
		return tempByte;
	}

	/**
	 * 字节数组异或运算
	 *
	 * @param byteOne
	 * @param byteTwo
	 * @return
	 */
	public static byte[] xor(byte[] byteOne, byte[] byteTwo) {
		byte[] tempByte = new byte[byteOne.length];
		for (int flag = 0; flag < tempByte.length; flag++) {
			tempByte[flag] = (byte) (byteOne[flag] ^ byteTwo[flag]);
		}
		return tempByte;
	}

	/**
	 *
	 *
	 * @return
	 */
	public static String paddingLen(String lenHex) {
		while (lenHex.length() < 4) {
			lenHex = "0" + lenHex;
		}
		return lenHex;
	}

	public static String paddingMacData(String data) {
		data = data + "80";
		while (data.length() % 32 != 0) {
			data = data + "00";
		}
		return data;
	}

	public static String paddingEncryptData(String data) {
		if (data.length() % 32 != 0) {
			data = data + "80";
		}

		while (data.length() % 32 != 0) {
			data = data + "00";
		}
		return data;
	}

	public static String paddingEncryptDataToString(String data) {
		if (data.length() % 32 != 0) {
			data = data + "80";
		}

		while (data.length() % 32 != 0) {
			data = data + "00";
		}
		return data;
	}

	public static String paddingDecryptData(String data) {
		byte[] bytes = BaseUtil.hexStringToBytes(data);
		for (int i = 1; i < bytes.length; i++) {
			if (bytes[i - 1] == 125 && bytes[i] == -128) {
				return BaseUtil.bytesToHexString(Arrays.copyOfRange(bytes, 0, i));
			}
		}
		return data;
	}

	/**
	 * 填充数据
	 * 
	 * @param data
	 * @param len
	 * @return
	 */
	public static String padding(String data, int len) {
		while (data.length() < len) {
			data = "0" + data;
		}
		return data;
	}

	/**
	 * 封装ECCCIPHERBLOB数据 密文数据分为3份，第一份长64位，第二份128位，第三份剩余
	 * 
	 * @param data 密文数据
	 * @param len  明文长度
	 * @return
	 */
	public static String packageEccipherblobData(String data) {
		if (data == null || data.length() < 172) {
			return null;
		}
		StringBuilder sb = new StringBuilder();
		sb.append("0000000000000000000000000000000000000000000000000000000000000000");
		sb.append(data.substring(0, 64));
		sb.append("0000000000000000000000000000000000000000000000000000000000000000");
		sb.append(data.substring(64, 64 + 128));
		int length = data.substring(64 + 128).length() / 2;
		String len = String.format("%02x", length);
		sb.append(len + "000000");
		sb.append(data.substring(64 + 128));
		sb.append("00");
		return sb.toString();
	}
	/**
	 * 清理ECCCIPHERBLOB封装
	 * @param data
	 * @return
	 */
	public static String unpackageEccipherblobData(String data) {
	    if (data == null || data.length() < 172) {
	        return null;
	    }
	    // 去掉固定的64字节头部
	    String withoutHeader = data.substring(64);
	    
	    // 获取64字节的数据部分
	    String one = withoutHeader.substring(0, 64);
	    
	    // 获取128字节数据部分
	   String two = withoutHeader.substring(128,256);
	    
	    // 获取剩余的数据部分
	    String three = withoutHeader.substring(256+8, withoutHeader.length()-2);
	    
	    // 拼接最终结果
	    StringBuilder sb = new StringBuilder();
	    sb.append(one);
	    sb.append(two);
	    sb.append(three);
	    
	    return sb.toString();
	}

}
