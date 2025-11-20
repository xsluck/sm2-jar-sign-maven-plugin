# SM2 JAR Sign Maven Plugin

一个用于在 Maven 构建过程中自动使用国密 SM2 算法对 JAR 包进行签名的插件。

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
- ✅ 自动集成到 Maven 构建生命周期
- ✅ 支持多环境配置（开发/测试/生产）
- ✅ 支持 PEM 格式密钥和证书
- ✅ 自动验证签名完整性
- ✅ 详细的构建日志输出
- ✅ 支持跳过签名（开发环境）

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

### 2. 准备密钥和证书

生成 SM2 密钥对和证书：

```bash
# 使用 GmSSL 生成
gmssl sm2keygen -pass "changeit" -out sm2.key -pubout sm2.pub
gmssl certgen -C CN -ST Beijing -L Beijing -O "MyOrg" -OU "IT" \
    -CN "JAR Signer" -days 3650 -key sm2.key -pass "changeit" -out sm2.crt

# 转换为 PKCS#8 格式（Java 兼容）
openssl pkcs8 -topk8 -nocrypt -in sm2.key -out sm2-pkcs8.key
```

### 3. 配置项目 pom.xml

```xml
<build>
    <plugins>
        <plugin>
            <groupId>com.example</groupId>
            <artifactId>sm2-jar-sign-maven-plugin</artifactId>
            <version>1.0.0</version>
            <executions>
                <execution>
                    <id>sign-jar</id>
                    <phase>package</phase>
                    <goals>
                        <goal>sign</goal>
                    </goals>
                    <configuration>
                        <jarFile>${project.build.directory}/${project.build.finalName}.jar</jarFile>
                        <keyFile>${project.basedir}/keystore/sm2-pkcs8.key</keyFile>
                        <certFile>${project.basedir}/keystore/sm2.crt</certFile>
                        <alias>sm2signer</alias>
                    </configuration>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```

### 4. 构建并签名

```bash
mvn clean package
```

## ⚙️ 配置说明

### 插件参数

| 参数 | 类型 | 必需 | 默认值 | 说明 |
|------|------|------|--------|------|
| `jarFile` | File | 是 | - | 要签名的 JAR 文件路径 |
| `keyFile` | File | 是 | - | SM2 私钥文件路径（PEM 格式，PKCS#8） |
| `certFile` | File | 是 | - | SM2 证书文件路径（PEM 格式） |
| `alias` | String | 否 | sm2signer | 签名别名 |
| `skip` | Boolean | 否 | false | 是否跳过签名 |
| `outputFile` | File | 否 | - | 输出文件路径（默认覆盖原文件） |

### 使用 Properties 配置

在 `pom.xml` 中定义属性：

```xml
<properties>
    <!-- 签名配置 -->
    <jar.sign.enabled>true</jar.sign.enabled>
    <jar.sign.keyfile>${project.basedir}/keystore/sm2-pkcs8.key</jar.sign.keyfile>
    <jar.sign.certfile>${project.basedir}/keystore/sm2.crt</jar.sign.certfile>
    <jar.sign.alias>sm2signer</jar.sign.alias>
</properties>

<build>
    <plugins>
        <plugin>
            <groupId>com.example</groupId>
            <artifactId>sm2-jar-sign-maven-plugin</artifactId>
            <version>1.0.0</version>
            <configuration>
                <jarFile>${project.build.directory}/${project.build.finalName}.jar</jarFile>
                <keyFile>${jar.sign.keyfile}</keyFile>
                <certFile>${jar.sign.certfile}</certFile>
                <alias>${jar.sign.alias}</alias>
                <skip>${skipJarSign}</skip>
            </configuration>
        </plugin>
    </plugins>
</build>
```

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

    <!-- 测试环境 - 使用测试密钥 -->
    <profile>
        <id>test</id>
        <properties>
            <skipJarSign>false</skipJarSign>
            <jar.sign.keyfile>${project.basedir}/keystore/test-sm2.key</jar.sign.keyfile>
            <jar.sign.certfile>${project.basedir}/keystore/test-sm2.crt</jar.sign.certfile>
        </properties>
    </profile>

    <!-- 生产环境 - 使用生产密钥 -->
    <profile>
        <id>prod</id>
        <properties>
            <skipJarSign>false</skipJarSign>
            <jar.sign.keyfile>${project.basedir}/keystore/prod-sm2.key</jar.sign.keyfile>
            <jar.sign.certfile>${project.basedir}/keystore/prod-sm2.crt</jar.sign.certfile>
        </properties>
    </profile>
</profiles>
```

## 📝 使用示例

### 基本使用

```bash
# 开发环境（跳过签名）
mvn clean package

# 生产环境（启用签名）
mvn clean package -Pprod

# 测试环境
mvn clean package -Ptest
```

### 命令行覆盖配置

```bash
# 指定不同的密钥文件
mvn clean package -Djar.sign.keyfile=/path/to/custom.key

# 临时启用签名
mvn clean package -DskipJarSign=false

# 指定输出文件
mvn clean package -Djar.sign.output=/path/to/signed.jar
```

### 验证签名

使用 JDK 自带的 jarsigner 验证：

```bash
jarsigner -verify -verbose -certs target/your-app-1.0.0.jar
```

使用自定义验证工具：

```bash
java -cp target/your-app-1.0.0.jar:lib/* \
    com.example.security.JarSignatureVerifier \
    target/your-app-1.0.0.jar
```

## 🔐 密钥管理

### 密钥格式要求

插件支持以下密钥格式：

**私钥格式**：
- ✅ PKCS#8 PEM 格式（推荐）
- ✅ EC PRIVATE KEY PEM 格式（需要转换）

**证书格式**：
- ✅ X.509 PEM 格式
- ✅ X.509 DER 格式

### 密钥格式转换

如果您的私钥是 `EC PRIVATE KEY` 格式，需要转换为 `PKCS#8` 格式：

```bash
# 检查密钥格式
head -1 sm2.key
# 如果显示 "-----BEGIN EC PRIVATE KEY-----"，需要转换

# 转换为 PKCS#8 格式
openssl pkcs8 -topk8 -nocrypt -in sm2.key -out sm2-pkcs8.key

# 验证转换结果
head -1 sm2-pkcs8.key
# 应该显示 "-----BEGIN PRIVATE KEY-----"
```

### 密钥存储建议

**目录结构**：
```
your-project/
├── keystore/
│   ├── dev/
│   │   ├── sm2-pkcs8.key
│   │   └── sm2.crt
│   ├── test/
│   │   ├── sm2-pkcs8.key
│   │   └── sm2.crt
│   └── prod/
│       ├── sm2-pkcs8.key
│       └── sm2.crt
├── pom.xml
└── src/
```

**安全建议**：
- ⚠️ 不要将生产环境密钥提交到版本控制系统
- ✅ 使用 `.gitignore` 排除密钥文件
- ✅ 生产密钥应该存储在安全的密钥管理系统中
- ✅ 使用环境变量或加密配置传递密钥路径

**.gitignore 示例**：
```gitignore
# 排除生产密钥
keystore/prod/
*.key
*.p12
*.jks

# 允许测试密钥（可选）
!keystore/test/*.key
```

### 使用环境变量

```xml
<properties>
    <jar.sign.keyfile>${env.JAR_SIGN_KEY_FILE}</jar.sign.keyfile>
    <jar.sign.certfile>${env.JAR_SIGN_CERT_FILE}</jar.sign.certfile>
    <jar.sign.password>${env.JAR_SIGN_PASSWORD}</jar.sign.password>
</properties>
```

```bash
# 设置环境变量
export JAR_SIGN_KEY_FILE=/secure/path/sm2-pkcs8.key
export JAR_SIGN_CERT_FILE=/secure/path/sm2.crt
export JAR_SIGN_PASSWORD=your_password

# 构建
mvn clean package -Pprod
```

## ❓ 常见问题

### Q1: 报错 "encoded key spec not recognized"

**原因**：私钥格式不正确，可能是 `EC PRIVATE KEY` 格式而不是 `PKCS#8` 格式。

**解决方案**：
```bash
openssl pkcs8 -topk8 -nocrypt -in sm2.key -out sm2-pkcs8.key
```

### Q2: 报错 "Certificate chain not found"

**原因**：证书文件路径不正确或证书格式不支持。

**解决方案**：
- 检查证书文件是否存在
- 确保证书是 PEM 格式
- 验证证书内容：`openssl x509 -in sm2.crt -text -noout`

### Q3: 如何在 CI/CD 中使用？

**Jenkins Pipeline**：
```groovy
pipeline {
    agent any
    environment {
        JAR_SIGN_KEY = credentials('jar-sign-key')
        JAR_SIGN_CERT = credentials('jar-sign-cert')
    }
    stages {
        stage('Build and Sign') {
            steps {
                sh '''
                    mvn clean package -Pprod \
                        -Djar.sign.keyfile=$JAR_SIGN_KEY \
                        -Djar.sign.certfile=$JAR_SIGN_CERT
                '''
            }
        }
    }
}
```

**GitLab CI**：
```yaml
build:
  stage: build
  script:
    - echo "$JAR_SIGN_KEY" > /tmp/sm2.key
    - echo "$JAR_SIGN_CERT" > /tmp/sm2.crt
    - openssl pkcs8 -topk8 -nocrypt -in /tmp/sm2.key -out /tmp/sm2-pkcs8.key
    - mvn clean package -Pprod
        -Djar.sign.keyfile=/tmp/sm2-pkcs8.key
        -Djar.sign.certfile=/tmp/sm2.crt
  artifacts:
    paths:
      - target/*.jar
```

### Q4: 如何验证签名是否成功？

**方法 1：使用 jarsigner**
```bash
jarsigner -verify -verbose target/your-app.jar
```

**方法 2：检查 META-INF 目录**
```bash
jar -tf target/your-app.jar | grep META-INF
# 应该看到 .SF 和 .SM2 文件
```

**方法 3：使用自定义验证工具**
```bash
java -jar jar-signature-verifier.jar target/your-app.jar
```

### Q5: 签名会影响性能吗？

签名过程会增加构建时间，通常增加 5-30 秒，取决于 JAR 包大小。建议：
- 开发环境跳过签名（`-Pdev`）
- 仅在测试和生产环境启用签名
- 使用 CI/CD 自动化签名过程

## 🎯 最佳实践

### 1. 密钥管理

```bash
# 为不同环境生成独立的密钥对
./generate-keys.sh dev
./generate-keys.sh test
./generate-keys.sh prod

# 生产密钥使用密码保护
gmssl sm2keygen -pass "strong_password" -out prod-sm2.key
```

### 2. 自动化构建

```xml
<!-- 在 package 阶段自动签名 -->
<execution>
    <id>sign-jar</id>
    <phase>package</phase>
    <goals>
        <goal>sign</goal>
    </goals>
</execution>

<!-- 在 verify 阶段自动验证 -->
<execution>
    <id>verify-signature</id>
    <phase>verify</phase>
    <goals>
        <goal>verify</goal>
    </goals>
</execution>
```

### 3. 运行时验证

在应用启动时验证签名：

```java
public class Application {
    public static void main(String[] args) {
        // 启动时验证签名
        JarSignatureVerifier.checkSignatureOnStartup();
        
        // 继续正常启动
        SpringApplication.run(Application.class, args);
    }
}
```

### 4. 版本控制

```xml
<!-- 记录签名信息到 MANIFEST.MF -->
<manifestEntries>
    <Signature-Version>1.0</Signature-Version>
    <Signature-Algorithm>SM3withSM2</Signature-Algorithm>
    <Signature-Date>${maven.build.timestamp}</Signature-Date>
    <Signed-By>${user.name}</Signed-By>
</manifestEntries>
```

### 5. 监控和日志

```xml
<configuration>
    <verbose>true</verbose>
    <logFile>${project.build.directory}/jar-sign.log</logFile>
</configuration>
```

## 📚 相关资源

- [GmSSL 官方文档](http://gmssl.org/)
- [BouncyCastle 文档](https://www.bouncycastle.org/documentation.html)
- [国密算法标准](http://www.gmbz.org.cn/)
- [Maven 插件开发指南](https://maven.apache.org/plugin-developers/)

## 📄 许可证

本项目采用 Apache License 2.0 许可证。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📧 联系方式

- 项目主页：https://github.com/your-org/sm2-jar-sign-maven-plugin
- 问题反馈：https://github.com/your-org/sm2-jar-sign-maven-plugin/issues

---

**版本**: 1.0.0  
**最后更新**: 2025-11-20

