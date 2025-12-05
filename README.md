# SM2 JAR Sign Maven Plugin

一个用于在 Maven 构建过程中自动使用国密 SM2 算法对 JAR/WAR 包进行签名的插件。

## 📋 目录

- [功能特性](#功能特性)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [使用示例](#使用示例)
- [密钥管理](#密钥管理)
- [常见问题](#常见问题)
- [最佳实践](#最佳实践)

## ✨ 功能特性

- ✅ 支持国密 SM2 算法签名
- ✅ 支持 SM3 摘要算法
- ✅ **支持证书链**（多个证书拼接在一起的 PEM 文件）
- ✅ **自动检测 JAR/WAR 文件**（无需手动指定）
- ✅ **同时支持 JAR 和 WAR 包签名**
- ✅ 自动集成到 Maven 构建生命周期
- ✅ 支持多环境配置（开发/测试/生产）
- ✅ 支持 PEM 格式密钥和证书（PKCS#8 和 EC PRIVATE KEY）
- ✅ 自动验证签名完整性
- ✅ 详细的构建日志输出
- ✅ 支持跳过签名（开发环境）
- ✅ 签名时显示文件统计信息
- ✅ 验证时显示完整的证书链信息
- ✅ 证书有效期检查和过期提醒
- ✅ 证书链验证

## 🔧 环境要求

- **JDK**: 1.8 或更高版本
- **Maven**: 3.6.0 或更高版本
- **BouncyCastle**: 1.70 或更高版本
- **操作系统**: Linux / macOS / Windows

## 🚀 快速开始

### 1. 安装插件

将插件安装到本地 Maven 仓库：

```bash
cd sm2-jar-sign-maven-plugin
mvn clean install
```

### 2. 准备密钥和证书链

生成 SM2 密钥对和证书链：

```bash
# 使用 GmSSL 生成根证书
# 生成根证书密钥
gmssl sm2keygen -pass "your_password" -out ROOT_CA_KEY.pem
# 生成根证书
gmssl certgen -C CN -ST Beijing -L Changping -O "Your Organization" -OU "Your Department" -CN ROOTCA \
    -days 3650 -key ROOT_CA_KEY.pem -pass "your_password" -out ROOT_CA_CERT.pem -key_usage keyCertSign -key_usage cRLSign

# 生成叶子证书（由根证书签发）
gmssl sm2keygen -pass "your_password" -out LEAF_CERT_KEY.pem
# 生成证书请求
gmssl reqgen -C CN -ST Beijing -L Changping -O "Your Organization" -OU "Your Department" -CN "Your Common Name" \
    -key LEAF_CERT_KEY.pem -pass "your_password" -out LEAF_CERT_REQ.pem
# 签发
gmssl reqsign -in LEAF_CERT_REQ.pem -days 3650 -key_usage keyCertSign -key_usage digitalSignature -key_usage nonRepudiation -path_len_constraint 0 \
    -cacert ROOT_CA_CERT.pem -key ROOT_CA_KEY.pem -pass "your_password" -out LEAF_CERT.pem


# 合并为证书链文件（叶子证书在前，根证书在后）
cat LEAF_CERT.pem ROOT_CA_CERT.pem > cert-chain.pem
```

### 3. 配置项目 pom.xml

```xml
<build>
    <plugins>
        <plugin>
            <groupId>com.github.xsluck</groupId>
            <artifactId>sm2-jar-sign-maven-plugin</artifactId>
            <version>0.0.5</version>
            <configuration>
                <keyFile>${project.basedir}/keystore/LEAF_CERT_KEY.pem</keyFile>
                <certChainFile>${project.basedir}/keystore/cert-chain.pem</certChainFile>
            </configuration>
            <executions>
                <execution>
                    <goals>
                        <goal>sign</goal>
                    </goals>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```

### 4. 构建并签名

```bash
# 签名并自动验证（推荐）
mvn clean package

# 签名后会自动验证签名是否正确
# 如果验证失败，构建会中断
```

## ⚙️ 配置说明

### 插件参数

| 参数                   | 类型    | 必需 | 默认值 | 说明                                  |
| ---------------------- | ------- | ---- | ------ | ------------------------------------- |
| `jarFile`              | File    | 否   | 自动   | 要签名的 JAR/WAR 文件路径（自动检测） |
| `keyFile`              | File    | 是   | -      | SM2 私钥文件路径（PEM 格式，PKCS#8）  |
| `certChainFile`        | File    | 是   | -      | 证书链文件路径（多个 PEM 证书拼接）   |
| `password`             | String  | 否   | -      | 私钥密码（如果私钥加密）              |
| `skip`                 | Boolean | 否   | false  | 是否跳过签名                          |
| `outputFile`           | File    | 否   | -      | 输出文件路径（默认覆盖原文件）        |
| `verify`               | Boolean | 否   | true   | 签名后是否自动验证                    |
| `strictCertValidation` | Boolean | 否   | true   | 是否启用严格证书链验证                |

### 证书链文件格式

证书链文件是多个 PEM 格式证书拼接在一起，**叶子证书（签名证书）在前，CA/根证书在后**：

```
-----BEGIN CERTIFICATE-----
MIICUDCCAfag... （叶子证书/终端证书）
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICOzCCAeGg... （CA证书/中间证书）
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB... （根证书，可选）
-----END CERTIFICATE-----
```

### 自动检测 JAR/WAR 文件

插件会自动检测项目的构建产物：

- 对于 `<packaging>jar</packaging>` 项目，自动查找 `target/${artifactId}-${version}.jar`
- 对于 `<packaging>war</packaging>` 项目，自动查找 `target/${artifactId}-${version}.war`

如需手动指定，使用 `jarFile` 参数。

### 多环境配置

使用 Maven Profile 配置不同环境：

```xml
<profiles>
    <!-- 开发环境 - 跳过签名 -->
    <profile>
        <id>dev</id>
        <activation>
            <activeByDefault>true</activeByDefault>
        </activation>
        <properties>
            <skipJarSign>true</skipJarSign>
        </properties>
    </profile>

    <!-- 生产环境 - 启用签名 -->
    <profile>
        <id>prod</id>
        <properties>
            <skipJarSign>false</skipJarSign>
            <jar.sign.keyfile>${project.basedir}/keystore/prod.key</jar.sign.keyfile>
            <jar.sign.certchain>${project.basedir}/keystore/prod-chain.pem</jar.sign.certchain>
        </properties>
    </profile>
</profiles>
```

## 📝 使用示例

### 最简配置

```xml
<plugin>
    <groupId>com.github.xsluck</groupId>
    <artifactId>sm2-jar-sign-maven-plugin</artifactId>
    <version>0.0.5</version>
    <configuration>
        <keyFile>keystore/private.key</keyFile>
        <certChainFile>keystore/cert-chain.pem</certChainFile>
    </configuration>
    <executions>
        <execution>
            <goals>
                <goal>sign</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

### 带密码的加密私钥

```xml
<configuration>
    <keyFile>keystore/encrypted-private.key</keyFile>
    <certChainFile>keystore/cert-chain.pem</certChainFile>
    <password>${jar.sign.password}</password>
</configuration>
```

使用时传递密码：

```bash
mvn clean package -Djar.sign.password=your-password
```

### 命令行覆盖配置

```bash
# 跳过签名
mvn clean package -Dskip=true

# 指定不同的密钥文件
mvn clean package -DkeyFile=/path/to/custom.key -DcertChainFile=/path/to/chain.pem
```

### 构建输出示例

```
[INFO] ========================================
[INFO] 开始使用SM2算法签名JAR包
[INFO] JAR文件: /path/to/your-app-1.0.0.jar
[INFO] 私钥文件: /path/to/private.key
[INFO] 证书链文件: /path/to/cert-chain.pem
[INFO] 严格证书验证: true
[INFO] ========================================
[INFO] 解压JAR包...
[INFO] 加载私钥和证书链...
[INFO] 成功加载证书链，共 2 个证书
[INFO] 验证证书链...
[INFO] ✓ 证书链验证通过
[INFO] 创建签名文件...
[INFO] 已为 1028 个文件添加 SM3 摘要
[INFO] 创建包含证书链的签名块（2 个证书）
[INFO] 重新打包JAR...
[INFO] JAR包签名完成: /path/to/your-app-1.0.0.jar
[INFO] ========================================
[INFO]
[INFO] ========================================
[INFO] 开始验证签名...
[INFO] ========================================
[INFO] 找到签名文件: META-INF/CN=JAR Signer....SF
[INFO] 找到签名块文件: META-INF/CN=JAR Signer....SM2
[INFO]
[INFO] 证书链信息（共 2 个证书）:
[INFO]   证书 1:
[INFO]     主题: CN=JAR Signer, OU=IT, O=MyOrg
[INFO]     颁发者: CN=ROOT CA, OU=IT, O=MyOrg
[INFO]     证书状态: ✓ 有效
[INFO]   证书 2:
[INFO]     主题: CN=ROOT CA, OU=IT, O=MyOrg
[INFO]     类型: 自签名证书（根证书）
[INFO]
[INFO] 总文件数: 1028
[INFO] 已验证文件数: 1028
[INFO] ========================================
[INFO] ✓ 签名验证通过 - JAR包已正确签名
[INFO] ========================================
```

## 🔐 密钥管理

### 密钥格式要求

**私钥格式**：

- ✅ PKCS#8 PEM 格式（未加密）- 推荐开发环境
- ✅ PKCS#8 PEM 格式（加密）- **推荐生产环境**
- ✅ EC PRIVATE KEY PEM 格式（自动转换）

**证书链格式**：

- ✅ 多个 X.509 PEM 格式证书拼接
- ✅ 叶子证书在前，根证书在后

### 密钥格式转换

```bash
# 检查密钥格式
head -1 sm2.key

# 如果是 EC PRIVATE KEY 格式，转换为 PKCS#8
openssl pkcs8 -topk8 -nocrypt -in sm2.key -out sm2-pkcs8.key
```

### 创建证书链文件

```bash
# 方法 1：直接拼接
cat leaf.crt intermediate.crt root.crt > cert-chain.pem

# 方法 2：使用 echo
echo "$(cat leaf.crt)" > cert-chain.pem
echo "$(cat root.crt)" >> cert-chain.pem
```

### 安全建议

- ⚠️ 不要将生产环境密钥提交到版本控制系统
- ✅ 使用 `.gitignore` 排除密钥文件
- ✅ 生产密钥应该存储在安全的密钥管理系统中
- ✅ 使用环境变量或加密配置传递密钥路径

## 🔐 运行时签名验证

### 应用启动时验证签名

插件提供了运行时验证工具类 `JarSignatureVerifier`，可以在应用启动时验证 JAR 包签名。

#### 使用方法

```java
import com.github.xsluck.utils.JarSignatureVerifier;

public class Application {
    public static void main(String[] args) {
        // 启动时验证签名（传入启动类）
        JarSignatureVerifier.checkSignatureOnStartup(true, Application.class);

        // 继续正常启动
        SpringApplication.run(Application.class, args);
    }
}
```

#### 验证原理

1. 从 JAR 包内部的签名块文件（`.SM2`）中提取证书链
2. 验证证书链的完整性
3. 从叶子证书中获取公钥
4. 使用公钥验证签名文件（`.SF`）的签名
5. 验证 MANIFEST.MF 的摘要
6. 验证所有文件的 SM3 摘要

**重点：** 公钥在证书中，证书在 JAR 包内部，无需外部文件！

## ❓ 常见问题

### Q1: 报错 "证书链文件不存在"

**解决方案**：确保证书链文件路径正确，且文件包含完整的证书链。

### Q2: 报错 "证书链验证失败"

**原因**：证书链不完整或证书顺序错误。

**解决方案**：

- 确保叶子证书在前，根证书在后
- 确保证书之间有签发关系

### Q3: 自动检测 JAR 文件失败

**原因**：项目打包类型不是 jar 或 war。

**解决方案**：手动指定 `jarFile` 参数。

### Q4: 如何在 CI/CD 中使用？

**Jenkins Pipeline**：

```groovy
pipeline {
    agent any
    environment {
        JAR_SIGN_KEY = credentials('jar-sign-key')
        JAR_SIGN_CERT_CHAIN = credentials('jar-sign-cert-chain')
    }
    stages {
        stage('Build and Sign') {
            steps {
                sh '''
                    mvn clean package \
                        -DkeyFile=$JAR_SIGN_KEY \
                        -DcertChainFile=$JAR_SIGN_CERT_CHAIN
                '''
            }
        }
    }
}
```

## 🎯 最佳实践

### 1. 密钥管理

```
your-project/
├── keystore/
│   ├── dev/
│   │   ├── private.key
│   │   └── cert-chain.pem
│   └── prod/
│       ├── private.key
│       └── cert-chain.pem
├── pom.xml
└── src/
```

### 2. 证书有效期监控

插件会在验证时显示证书有效期，如果证书将在 90 天内过期会显示警告。

### 3. 版本控制

**.gitignore 示例**：

```gitignore
# 排除生产密钥
keystore/prod/
*.key

# 允许证书（公开信息）
!keystore/**/*.pem
```

## 📚 相关资源

- [GmSSL 官方文档](http://gmssl.org/)
- [BouncyCastle 文档](https://www.bouncycastle.org/documentation.html)
- [国密算法标准](http://www.gmbz.org.cn/)
- [Maven 插件开发指南](https://maven.apache.org/plugin-developers/)

## 📄 许可证

本项目采用 Apache License 2.0 许可证。

---

## 📝 更新日志

### v0.0.5 (最新)

- ✨ **重大更新**：将 `certFile` 和 `caCertFile` 合并为 `certChainFile`（证书链文件）
- ✨ **新增**：自动检测项目的 JAR/WAR 文件，`jarFile` 参数改为可选
- ✨ **新增**：同时支持 JAR 和 WAR 包签名
- ✨ **新增**：完整的证书链验证和显示
- ✨ **改进**：`strictCertValidation` 默认值改为 `true`
- 🐛 修复：证书链提取范围过小的问题

### v0.0.3

- 🐛 **重要修复**：签名后 JAR 包无法运行的问题
- 🐛 修复：MANIFEST.MF 主属性丢失（如 Main-Class、Class-Path）
- 📝 改进：保留原始 MANIFEST.MF 的所有属性

### v0.0.2

- ✨ 新增：签名时显示处理的文件数量统计
- ✨ 新增：验证时显示完整的证书信息
- ✨ 新增：证书有效期检查和过期提醒
- 🐛 修复：递归处理子目录文件的签名问题

### v0.0.1

- ✨ 基本的 SM2 JAR 签名功能
- ✨ 支持 SM3 摘要算法
- ✨ 自动验证签名完整性

---

**当前版本**: 0.0.5  
**最后更新**: 2025-12-05
