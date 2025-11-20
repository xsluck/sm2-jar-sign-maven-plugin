package com.github.xsluck.utils;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Time;

/**
 * Created by LJM on 2017/6/28.
 */
public class CertUtil {

    /**
     * 加载国密证书
     *
     * @param certStr
     * @return
     */
    public static Certificate loadSM2Base64Cert(String certStr) throws Exception {
        ASN1InputStream aln = null;
        ByteArrayInputStream byteArrayInputStream = null;
        Certificate cert = null;
        try {
            byteArrayInputStream = new ByteArrayInputStream(Base64.getDecoder().decode(certStr));
            aln = new ASN1InputStream(byteArrayInputStream);
            ASN1Sequence seq = (ASN1Sequence) aln.readObject();
            cert = Certificate.getInstance(seq);
        } catch (Exception e) {
            throw e;
        } finally {
            try {
                aln.close();
                byteArrayInputStream.close();
            } catch (Exception e2) {
            }
        }
        return cert;
    }

    /**
     * 加载国密证书
     *
     * @param certStr
     * @return
     */
    public static Certificate loadSM2HexCert(String certStr) throws Exception {
        ASN1InputStream aln = null;
        ByteArrayInputStream byteArrayInputStream = null;
        Certificate cert = null;
        try {
            byteArrayInputStream = new ByteArrayInputStream(BaseUtil.hexStringToBytes(certStr));
            aln = new ASN1InputStream(byteArrayInputStream);
            ASN1Sequence seq = (ASN1Sequence) aln.readObject();
            cert = Certificate.getInstance(seq);
        } catch (Exception e) {
            throw e;
        } finally {
            try {
                aln.close();
                byteArrayInputStream.close();
            } catch (Exception e2) {
            }
        }
        return cert;
    }

    /**
     * 校验证书有效期
     *
     * @param certificate
     * @return
     */
    public static boolean checkDateValidity(Certificate certificate) {
        Time time = certificate.getEndDate();
        if (time.getDate().compareTo(new Date()) <= 0) {
            return false;
        }
        return true;
    }

    /**
     * 加载国密证书公钥
     *
     * @param certificate
     * @return
     */
    public static String loadSM2CertPublicKey(Certificate certificate) throws Exception {
        String publicKeyStr = null;
        try {
            ASN1Primitive publicKey = certificate.getSubjectPublicKeyInfo().getPublicKeyData().toASN1Primitive();
            byte[] encodedPublicKey = publicKey.getEncoded();
            String publicKeyStrTemp = BaseUtil.bytesToHexString(encodedPublicKey);
            publicKeyStr = publicKeyStrTemp.substring(8, publicKeyStrTemp.length());
        } catch (Exception e) {
            throw e;
        }
        return publicKeyStr;
    }

    /**
     * 加载国密证书公钥
     *
     * @param cert
     * @return
     */
    public static String loadSM2CertPublicKey(String cert) throws Exception {
        String publicKeyStr = null;
        try {
            Certificate certificate = loadSM2Base64Cert(cert);
            ASN1Primitive publicKey = certificate.getSubjectPublicKeyInfo().getPublicKeyData().toASN1Primitive();
            byte[] encodedPublicKey = publicKey.getEncoded();
            String publicKeyStrTemp = BaseUtil.bytesToHexString(encodedPublicKey);
            publicKeyStr = publicKeyStrTemp.substring(8, publicKeyStrTemp.length());
        } catch (Exception e) {
            throw e;
        }
        return publicKeyStr;
    }

    /**
     * 解析签名值
     *
     * @param certificate
     * @return
     * @throws Exception
     */
    public static String loadSignature(Certificate certificate) throws Exception {
        String signature = null;
        try {
            ASN1InputStream asnInputStream = new ASN1InputStream(
                    new ByteArrayInputStream(certificate.getSignature().getBytes()));
            ASN1Sequence asn1Sequence = (ASN1Sequence) asnInputStream.readObject();
            BigInteger rBigInteger = new BigInteger(asn1Sequence.getObjectAt(0).toString());
            BigInteger sBigInteger = new BigInteger(asn1Sequence.getObjectAt(1).toString());
            signature = rBigInteger.toString(16) + sBigInteger.toString(16);
        } catch (Exception e) {
            throw e;
        }
        return signature;
    }

    /**
     * 解析签名值
     *
     * @param sign
     * @return
     * @throws Exception
     */
    public static String loadSignature(String sign) throws Exception {
        String signature = null;
        try {
            ASN1InputStream asnInputStream = new ASN1InputStream(
                    new ByteArrayInputStream(BaseUtil.hexStringToBytes(sign)));
            ASN1Sequence asn1Sequence = (ASN1Sequence) asnInputStream.readObject();
            BigInteger rBigInteger = new BigInteger(asn1Sequence.getObjectAt(0).toString());
            BigInteger sBigInteger = new BigInteger(asn1Sequence.getObjectAt(1).toString());
            signature = rBigInteger.toString(16) + sBigInteger.toString(16);
        } catch (Exception e) {
            throw e;
        }
        return signature;
    }

    /**
     * 证书PEM编码
     * 
     * @param cert BASE64编码证书
     * @return
     */
    public static String encodeCertToPem(String cert) {
        StringBuffer certData = new StringBuffer();
        certData.append("-----BEGIN CERTIFICATE-----\n");
        certData.append(encodePem(cert));
        certData.append("-----END CERTIFICATE-----\n");
        return certData.toString();
    }

    /**
     * 私钥PEM解码
     * 
     * @param key BASE64密钥编码
     * @return
     * @throws Exception
     */
    public static String decodePemPriKeyToHex(String key) throws Exception {
        try {
            String keyHead = "-----BEGIN EC PRIVATE KEY-----";
            String signPriKey = key.substring(key.lastIndexOf(keyHead) + keyHead.length(),
                    key.lastIndexOf("-----END EC PRIVATE KEY-----"));
            signPriKey = signPriKey.replace("\n", "");

            ASN1InputStream asn1InputStream = new ASN1InputStream(Base64.getDecoder().decode(signPriKey));
            ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(asn1InputStream.readObject());

            ASN1Primitive pikAsn1Primitive = asn1Sequence.getObjectAt(1).toASN1Primitive();
            DEROctetString pikDEROctetString = (DEROctetString) pikAsn1Primitive;
            String pik = BaseUtil.bytesToHexString(pikDEROctetString.getOctets());
            return pik;
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

    /**
     * 私钥PEM编码
     * 
     * @param priKey BASE64密钥编码
     * @return
     */
    public static String encodeBase64PriKeyToPem(String priKey) {
        StringBuffer keyData = new StringBuffer();
        keyData.append("-----BEGIN EC PARAMETERS-----\n");
        keyData.append("BggqgRzPVQGCLQ==\n");
        keyData.append("-----END EC PARAMETERS-----\n");
        keyData.append("-----BEGIN EC PRIVATE KEY-----\n");
        keyData.append(encodePem(priKey));
        keyData.append("-----END EC PRIVATE KEY-----\n");
        return keyData.toString();
    }

    /**
     * 私钥PEM编码
     * 
     * @param priKey HEX密钥编码
     * @return
     */
    public static String encodeHexPriKeyToPem(String priKey, String pukKey) {
        StringBuffer keyData = new StringBuffer();
        keyData.append("-----BEGIN EC PARAMETERS-----\n");
        keyData.append("BggqgRzPVQGCLQ==\n");
        keyData.append("-----END EC PARAMETERS-----\n");
        keyData.append("-----BEGIN EC PRIVATE KEY-----\n");
        StringBuffer priKeyPem = new StringBuffer();
        priKeyPem.append("30770201010420");
        priKeyPem.append(priKey);
        priKeyPem.append("a00a06082a811ccf5501822da14403420004");
        priKeyPem.append(pukKey);
        String base64Key = Base64.getEncoder().encodeToString(BaseUtil.hexStringToBytes(priKey));
        keyData.append(encodePem(base64Key));
        keyData.append("-----END EC PRIVATE KEY-----\n");
        return keyData.toString();
    }

    /**
     * PEM编码
     * 
     * @param data
     * @return
     */
    private static String encodePem(String data) {
        StringBuffer pemData = new StringBuffer();
        for (int index = 0; index < data.length();) {
            int temp = index;
            index = index + 64;
            if (index < data.length()) {
                pemData.append(data.substring(temp, index)).append("\n");
            } else {
                pemData.append(data.substring(temp, data.length())).append("\n");
            }
        }
        return pemData.toString();
    }

}
