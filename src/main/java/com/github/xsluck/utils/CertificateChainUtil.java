package com.github.xsluck.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 证书链工具类 - 用于创建和验证证书链
 */
public class CertificateChainUtil {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * 证书链验证结果
     */
    public static class ChainValidationResult {
        private boolean valid;
        private String message;
        private List<String> errors = new ArrayList<>();
        private List<X509Certificate> validatedChain = new ArrayList<>();

        public boolean isValid() {
            return valid;
        }

        public void setValid(boolean valid) {
            this.valid = valid;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public void addError(String error) {
            this.errors.add(error);
        }

        public List<String> getErrors() {
            return errors;
        }

        public List<X509Certificate> getValidatedChain() {
            return validatedChain;
        }

        public void setValidatedChain(List<X509Certificate> chain) {
            this.validatedChain = chain;
        }
    }

    /**
     * 从文件加载 X.509 证书
     */
    public static X509Certificate loadCertificateFromFile(File certFile) throws Exception {
        try (FileInputStream fis = new FileInputStream(certFile)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            Certificate cert = cf.generateCertificate(fis);
            if (cert instanceof X509Certificate) {
                return (X509Certificate) cert;
            } else {
                throw new CertificateException("证书不是 X.509 格式");
            }
        }
    }

    /**
     * 从 PEM 文件加载证书链（支持多个证书拼接在一起的格式）
     * 证书顺序应该是：叶子证书在前，CA证书/根证书在后
     * 
     * @param certChainFile 包含证书链的 PEM 文件
     * @return 证书链列表（从叶子证书到根证书）
     */
    public static List<X509Certificate> loadCertificateChainFromFile(File certChainFile) throws Exception {
        List<X509Certificate> certChain = new ArrayList<>();

        try (FileInputStream fis = new FileInputStream(certChainFile)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

            // 使用 generateCertificates 可以一次性读取多个证书
            for (Certificate cert : cf.generateCertificates(fis)) {
                if (cert instanceof X509Certificate) {
                    certChain.add((X509Certificate) cert);
                } else {
                    throw new CertificateException("证书链中包含非 X.509 格式的证书");
                }
            }
        }

        if (certChain.isEmpty()) {
            throw new CertificateException("证书链文件中未找到有效证书");
        }

        return certChain;
    }

    /**
     * 从字节数组加载 X.509 证书
     */
    public static X509Certificate loadCertificateFromBytes(byte[] certBytes) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certBytes));
        if (cert instanceof X509Certificate) {
            return (X509Certificate) cert;
        } else {
            throw new CertificateException("证书不是 X.509 格式");
        }
    }

    /**
     * 验证证书链
     * 
     * @param certChain 证书链（从叶子证书到根证书）
     * @param trustedCA 可信的 CA 根证书（可选，如果为 null 则验证自签名）
     * @return 验证结果
     */
    public static ChainValidationResult validateCertificateChain(List<X509Certificate> certChain,
            X509Certificate trustedCA) {
        ChainValidationResult result = new ChainValidationResult();

        if (certChain == null || certChain.isEmpty()) {
            result.setValid(false);
            result.setMessage("证书链为空");
            return result;
        }

        try {
            // 1. 验证每个证书的有效期
            for (int i = 0; i < certChain.size(); i++) {
                X509Certificate cert = certChain.get(i);
                try {
                    cert.checkValidity();
                } catch (Exception e) {
                    result.setValid(false);
                    result.setMessage("证书 " + (i + 1) + " 已过期或未生效");
                    result.addError("证书主题: " + cert.getSubjectDN());
                    result.addError("有效期: " + cert.getNotBefore() + " 至 " + cert.getNotAfter());
                    return result;
                }
            }

            // 2. 验证证书链的签名关系
            for (int i = 0; i < certChain.size() - 1; i++) {
                X509Certificate current = certChain.get(i);
                X509Certificate issuer = certChain.get(i + 1);

                // 验证当前证书是否由下一个证书签发
                if (!verifyCertificateSignature(current, issuer)) {
                    result.setValid(false);
                    result.setMessage("证书链验证失败：证书 " + (i + 1) + " 的签名无效");
                    result.addError("证书主题: " + current.getSubjectDN());
                    result.addError("颁发者: " + current.getIssuerDN());
                    result.addError("期望的签发者: " + issuer.getSubjectDN());
                    return result;
                }
            }

            // 3. 验证根证书
            X509Certificate rootCert = certChain.get(certChain.size() - 1);

            if (trustedCA != null) {
                // 如果提供了可信 CA，验证根证书是否匹配或由其签发
                if (!rootCert.equals(trustedCA)) {
                    // 尝试验证根证书是否由可信 CA 签发
                    if (!verifyCertificateSignature(rootCert, trustedCA)) {
                        result.setValid(false);
                        result.setMessage("根证书不受信任");
                        result.addError("根证书: " + rootCert.getSubjectDN());
                        result.addError("可信 CA: " + trustedCA.getSubjectDN());
                        return result;
                    }
                }
            } else {
                // 如果没有提供可信 CA，验证根证书是否自签名
                if (!verifySelfSignedCertificate(rootCert)) {
                    result.setValid(false);
                    result.setMessage("根证书不是有效的自签名证书");
                    result.addError("证书主题: " + rootCert.getSubjectDN());
                    result.addError("证书颁发者: " + rootCert.getIssuerDN());
                    return result;
                }
            }

            result.setValid(true);
            result.setMessage("证书链验证通过");
            result.setValidatedChain(certChain);
            return result;

        } catch (Exception e) {
            result.setValid(false);
            result.setMessage("证书链验证异常: " + e.getMessage());
            result.addError("异常类型: " + e.getClass().getName());
            return result;
        }
    }

    /**
     * 验证证书是否由指定的颁发者签发
     */
    public static boolean verifyCertificateSignature(X509Certificate cert, X509Certificate issuer) {
        try {
            // 检查颁发者 DN 是否匹配
            if (!cert.getIssuerDN().equals(issuer.getSubjectDN())) {
                return false;
            }

            // 使用颁发者的公钥验证证书签名
            PublicKey issuerPublicKey = issuer.getPublicKey();
            cert.verify(issuerPublicKey, "BC");
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 验证自签名证书
     */
    public static boolean verifySelfSignedCertificate(X509Certificate cert) {
        try {
            // 检查主题和颁发者是否相同
            if (!cert.getSubjectDN().equals(cert.getIssuerDN())) {
                return false;
            }

            // 使用证书自己的公钥验证签名
            PublicKey publicKey = cert.getPublicKey();
            cert.verify(publicKey, "BC");
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 创建证书链的编码数据（用于存储到签名块）
     * 格式: [证书数量(4字节)] [证书1长度(4字节)] [证书1数据] [证书2长度] [证书2数据] ...
     */
    public static byte[] encodeCertificateChain(List<X509Certificate> certChain) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        // 写入证书数量
        int certCount = certChain.size();
        baos.write(intToBytes(certCount));

        // 写入每个证书
        for (X509Certificate cert : certChain) {
            byte[] certBytes = cert.getEncoded();
            baos.write(intToBytes(certBytes.length));
            baos.write(certBytes);
        }

        return baos.toByteArray();
    }

    /**
     * 从编码数据中解析证书链
     */
    public static List<X509Certificate> decodeCertificateChain(byte[] encodedData) throws Exception {
        List<X509Certificate> certChain = new ArrayList<>();
        ByteArrayInputStream bais = new ByteArrayInputStream(encodedData);

        // 读取证书数量
        byte[] countBytes = new byte[4];
        if (bais.read(countBytes) != 4) {
            throw new Exception("无法读取证书数量");
        }
        int certCount = bytesToInt(countBytes);

        // 读取每个证书
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        for (int i = 0; i < certCount; i++) {
            // 读取证书长度
            byte[] lengthBytes = new byte[4];
            if (bais.read(lengthBytes) != 4) {
                throw new Exception("无法读取证书 " + (i + 1) + " 的长度");
            }
            int certLength = bytesToInt(lengthBytes);

            // 读取证书数据
            byte[] certBytes = new byte[certLength];
            if (bais.read(certBytes) != certLength) {
                throw new Exception("无法读取证书 " + (i + 1) + " 的数据");
            }

            // 解析证书
            Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certBytes));
            if (cert instanceof X509Certificate) {
                certChain.add((X509Certificate) cert);
            } else {
                throw new Exception("证书 " + (i + 1) + " 不是 X.509 格式");
            }
        }

        return certChain;
    }

    /**
     * 创建包含证书链和签名的签名块
     * 格式: [证书链编码数据] [签名数据]
     */
    public static byte[] createSignatureBlockWithChain(List<X509Certificate> certChain, byte[] signatureBytes)
            throws Exception {
        byte[] chainData = encodeCertificateChain(certChain);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(chainData);
        baos.write(signatureBytes);

        return baos.toByteArray();
    }

    /**
     * 从签名块中提取证书链
     * 这个方法尝试解析新格式（包含证书链）和旧格式（单个证书）
     */
    public static List<X509Certificate> extractCertificateChainFromSignatureBlock(byte[] sigBlockData)
            throws Exception {
        List<X509Certificate> certChain = new ArrayList<>();

        try {
            // 尝试解析新格式（证书链）
            certChain = decodeCertificateChain(sigBlockData);
            if (!certChain.isEmpty()) {
                return certChain;
            }
        } catch (Exception e) {
            // 如果新格式解析失败，尝试旧格式（单个证书）
        }

        // 尝试旧格式：直接提取单个或多个证书
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        // 扩大搜索范围，支持更大的证书链（最大到数据长度减去签名长度）
        int maxSearchLength = Math.max(sigBlockData.length - 64, sigBlockData.length * 9 / 10);

        // 尝试不同的分割点提取证书
        for (int i = 300; i < maxSearchLength; i++) {
            try {
                byte[] certBytes = Arrays.copyOfRange(sigBlockData, 0, i);

                // 尝试用 generateCertificates 提取多个证书
                try {
                    ByteArrayInputStream bais = new ByteArrayInputStream(certBytes);
                    for (Certificate cert : cf.generateCertificates(bais)) {
                        if (cert instanceof X509Certificate) {
                            certChain.add((X509Certificate) cert);
                        }
                    }
                    if (!certChain.isEmpty()) {
                        return certChain;
                    }
                } catch (Exception ex) {
                    // 继续尝试单证书方式
                }

                // 单证书方式
                Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certBytes));
                if (cert instanceof X509Certificate) {
                    certChain.add((X509Certificate) cert);
                    return certChain;
                }
            } catch (Exception e) {
                // 继续尝试下一个分割点
            }
        }

        throw new Exception("无法从签名块中提取证书");
    }

    /**
     * 整数转字节数组（大端序）
     */
    private static byte[] intToBytes(int value) {
        return new byte[] { (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value };
    }

    /**
     * 字节数组转整数（大端序）
     */
    private static int bytesToInt(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) | ((bytes[1] & 0xFF) << 16) | ((bytes[2] & 0xFF) << 8) | (bytes[3] & 0xFF);
    }

    /**
     * 打印证书链信息
     */
    public static String printCertificateChainInfo(List<X509Certificate> certChain) {
        StringBuilder sb = new StringBuilder();
        sb.append("证书链信息 (共 ").append(certChain.size()).append(" 个证书):\n");

        for (int i = 0; i < certChain.size(); i++) {
            X509Certificate cert = certChain.get(i);
            sb.append("\n证书 ").append(i + 1).append(":\n");
            sb.append("  主题: ").append(cert.getSubjectDN()).append("\n");
            sb.append("  颁发者: ").append(cert.getIssuerDN()).append("\n");
            sb.append("  序列号: ").append(cert.getSerialNumber().toString(16).toUpperCase()).append("\n");
            sb.append("  有效期: ").append(cert.getNotBefore()).append(" 至 ").append(cert.getNotAfter()).append("\n");
            sb.append("  签名算法: ").append(cert.getSigAlgName()).append("\n");

            // 检查有效性
            try {
                cert.checkValidity();
                sb.append("  状态: ✓ 有效\n");
            } catch (Exception e) {
                sb.append("  状态: ✗ 已过期或未生效\n");
            }

            // 标识证书类型
            if (cert.getSubjectDN().equals(cert.getIssuerDN())) {
                sb.append("  类型: 自签名证书（根证书）\n");
            } else {
                sb.append("  类型: 中间证书或叶子证书\n");
            }
        }

        return sb.toString();
    }
}
