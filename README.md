# OnePlus Ace5 Ultra 内核构建项目

## 项目概述

这是一个基于 GitHub Actions 的自动化内核构建工作流，专为 OnePlus Ace5 Ultra 设备定制。项目支持多种 Root 管理器和性能优化功能，提供稳定可靠的内核构建解决方案。

## 核心功能特性

### Root 管理器支持
- **KernelSU Next** - 下一代内核级权限管理系统
- **SukiSU Ultra** - 增强版 SukiSU 权限管理框架

### 文件系统优化
- **SUSFS 文件系统** - 支持魔术挂载、路径重定向和符号链接欺骗功能

### 压缩算法选项
- **lz4kd** - 高效内存压缩算法（可选启用）
- **标准 lz4 + zstd** - 稳定可靠的压缩方案（默认选择）

### 网络性能优化
- **BBR TCP 拥塞控制** -BBR 网络加速算法

### 安全保护机制
- **Baseband-guard 防格机** - 内核层面阻止对关键分区/设备节点的非法写入
- **HMBird GKI 补丁** - 强制将 HMBIRD_OGKI 转换为 HMBIRD_GKI

### 已删除的特性

~~**KPM 模块支持（谨慎开启，可能导致无法开机）**: 可选启用内核模块功能~~(KPM经常被用于某些非法用途)

~~**风驰调度器**: 可选启用 sched_ext 风驰驱动~~（无法启用风驰调速器，删了省心）

~~**代理性能优化**~~（几乎没有用途，并且**联发科芯片有几率导致设备无法连接网络**）

### 多版本兼容性

- **Android 版本支持**：Android 14 / Android 15
- **内核版本支持**：6.1 / 6.6

## 快速开始指南

### 环境要求
- GitHub 账户
- 已 Fork 本项目到个人仓库

### 构建步骤

1. **访问 GitHub Actions**
   - 进入您 Fork 后的仓库页面
   - 点击顶部导航栏的 "Actions" 选项卡

2. **选择工作流**
   - 在左侧边栏选择 "Oneplus_Ace5_Ultra_GKI" 工作流

3. **配置构建参数**
   - 点击 "Run workflow" 按钮
   - 填写构建参数

4. **启动构建过程**
   - 点击 "Run workflow" 开始自动化构建
   - 构建过程通常需要 15-30 分钟

### 构建输出

构建完成后，在工作流的 Artifacts 区域可以下载AnyKernel3 刷机包

## 高级配置选项

### 自定义内核设置
用户可以通过以下方式自定义构建配置：

1. **修改工作流文件**
   - 调整 `KERNEL_SUFFIX` 参数自定义内核版本名称
   - 修改功能开关启用或禁用特定模块

2. **编辑内核配置文件**
   - 修改 `gki_defconfig` 中的配置选项
   - 添加自定义内核功能模块

### 支持与反馈

提出BUG反馈之前，请检查是否为[SukiSU-Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra)自身问题，因为其自身BUG较多。


<details>
<summary>SukiSU Ultra代码质量问题</summary>

包名抽象：com.sukisu.ultra、io.sukisu.ultra、zako.zako.zako

库文件命名混乱：libzako.so、libzakoboot.so、libzakosign.so 等，难以辨识功能

函数命名随意：susfsSUS_SU_0()、susfsSUS_SU_2() 等



项目存在大量不必要的 Shell 命令调用

```kotlin
// 反模式：通过 shell 命令进行文件操作
fun isPathExists(path: String): Boolean {
    return runCmd("file " + path).contains("No such file or directory")
}

// 正确做法应使用原生文件API
fun isPathExists(path: String): Boolean {
    return File(path).exists()
}
```

异常处理逻辑存在严重设计缺陷：

```kotlin
fun getKpmVersionUse(): String {
    return try {
        if (!rootAvailable()) return ""  // 早期返回违反单一职责原则
        val version = getKpmVersion()
        if (version.isEmpty()) "" else version
    } catch (e: Exception) {
        "Error: ${e.message}"  // 异常信息直接暴露给UI层
    }
}

// 调用方需要解析错误字符串
val kpmVersion = getKpmVersionUse()
!kpmVersion.startsWith("Error")  // 字符串解析判断错误状态
```

大量硬编码值：

```java
// 硬编码路径，缺乏配置抽象层
private static final String OUTSIDE_KPMMGR_PATH = "/data/adb/ksu/bin/kpmmgr";
private static final String OUTSIDE_SUSFSD_PATH = "/data/adb/ksu/bin/susfsd";
```

root 权限检测和使用的实现：

```kotlin
fun rootAvailable(): Boolean {
    return try {
        val process = Runtime.getRuntime().exec("su -c id")  // 不必要的权限检查
        process.waitFor() == 0
    } catch (_: Exception) {
        false
    }
}
```

v3.1.9 引入的模块签名验证存在严重设计问题：

未考虑兼容性，**没有任何说明就添加至正式版**

```c
uint32_t zako_file_verify_esig(file_handle_t fd, uint32_t flags) {
    size_t file_sz = zako_sys_file_sz(fd);

    void* buffer = zako_sys_file_map(fd, file_sz);

    if (buffer == NULL) {
        return ZAKO_FV_MMAP_FAILED;
    }

    void* buff_end = ApplyOffset(buffer, +(file_sz));
    uint64_t* r_magic = (uint64_t*) ApplyOffset(buff_end, -8);

    if (*r_magic != ZAKO_ESIGNATURE_MAGIC) { // ZAKO_ESIGNATURE_MAGIC = 0x7a616b6f7369676eull = 'zakosign'
        return ZAKO_FV_INVALID_HEADER;
    }

    uint64_t* sz = (uint64_t*) ApplyOffset(buff_end, -16);
    if (*sz == 0 || *sz > file_sz) {
        return ZAKO_FV_INVALID_HEADER;
    }

    struct zako_esignature* esign_buf = (struct zako_esignature*) ApplyOffset(sz, -*sz);

    /* Entire file footer is ESignature + ESignatureSize + ESignatureMagic
         which is *sz + sizeof(sz) + 8 = *sz + 16
       So, original file buffer will be FileSize - *sz - 16 */
    uint32_t result = zako_esign_verify(esign_buf, buffer, file_sz - *sz - 16, flags);

    zako_sys_file_unmap(buffer, file_sz);
    return result;
}

uint32_t zako_esign_verify(struct zako_esignature* esig, uint8_t* buff, size_t len, uint32_t flags) {
    if (esig->magic != ZAKO_ESIGNATURE_MAGIC) { // ZAKO_ESIGNATURE_MAGIC = 0x7a616b6f7369676eull = 'zakosign'
        return ZAKO_ESV_INVALID_HEADER;
    }

    if (esig->version != ZAKO_ESIGNATURE_VERSION) {
        if (esig->version > ZAKO_ESIGNATURE_VERSION) {
            return ZAKO_ESV_UNSUPPORTED_VERSION;
        } else {
            return ZAKO_ESV_OUTDATED_VERSION;
        }
    }

    uint32_t result = 0;
    EVP_PKEY* pubkey = NULL;

    OnFlag(flags, ZAKO_ESV_INTEGRITY_ONLY) {
        goto verify_integrity;
    }

    /* Verify Ceritificates */

    uint8_t cert_count = esig->cert_sz;
    struct zako_der_certificate* cstbl[200] = { 0 };

    uint8_t* data = &esig->data;
    size_t off = (size_t) 0;
    for (uint8_t i = 0; i < cert_count; i ++) {
        struct zako_der_certificate* cert = ApplyOffset(data, +off);
        cstbl[i] = cert;

        off += sizeof(struct zako_der_certificate) + cert->len;
    }

    result |= zako_keychain_verify(&esig->key, &cstbl);

verify_integrity:
    pubkey = zako_parse_public_raw(esig->key.public_key);

    if (zako_hash_verify(buff, len, esig->hash) != 1) {
        result |= ZAKO_ESV_VERFICATION_FAILED;
    }

    if (zako_verify_buffer(pubkey, esig->hash, ZAKO_HASH_LENGTH, esig->signature) != 1) {
        result |= ZAKO_ESV_VERFICATION_FAILED;
    }

    EVP_PKEY_free(pubkey);

    uint64_t now = (uint64_t) time(NULL);
    if (esig->created_at == 0) {
        result |= ZAKO_ESV_MISSING_TIMESTAMP;
    } else if (esig->created_at >= now) {
        result |= ZAKO_ESV_UNTRUSTED_TIMESTAMP;
    }

    return result;

}

X509_STORE **zako_trustchain_new()
{
  X509_STORE **safe;
  X509_STORE *v1;
  X509 *v2;

  safe = (X509_STORE **)zako_allocate_safe(0x18uLL);
  *safe = X509_STORE_new();
  safe[1] = (X509_STORE *)OPENSSL_sk_new_null();
  v1 = *safe;
  v2 = (X509 *)zako_x509_parse_pem(
                 "-----BEGIN CERTIFICATE-----\n"
                 "MIIB3zCCAZGgAwIBAgIUOa4KF6KfAg/Jerrx7AX1opSdNLEwBQYDK2VwMHExCzAJ\n"
                 "BgNVBAYTAkNIMRIwEAYDVQQHDAlHdWFuZ3pob3UxEjAQBgNVBAgMCUd1YW5nZG9u\n"
                 "ZzESMBAGA1UECgwJc2hpcmtuZWtvMRIwEAYDVQQLDAlzaGlya25la28xEjAQBgNV\n"
                 "BAMMCXNoaXJrbmVrbzAeFw0yNTA4MTAxNTU2MTRaFw0zNTA4MDgxNTU2MTRaMHEx\n"
                 "CzAJBgNVBAYTAkNIMRIwEAYDVQQHDAlHdWFuZ3pob3UxEjAQBgNVBAgMCUd1YW5n\n"
                 "ZG9uZzESMBAGA1UECgwJc2hpcmtuZWtvMRIwEAYDVQQLDAlzaGlya25la28xEjAQ\n"
                 "BgNVBAMMCXNoaXJrbmVrbzAqMAUGAytlcAMhAKyLThabZFGUsW/deKhLcmwlTF+H\n"
                 "KQ78bO6ohwzcgncWozswOTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIC\n"
                 "pDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAzAFBgMrZXADQQB1T6vftHjoaBNTBk85\n"
                 "E/HVR6jZZwq4UFJMRWpxpJ0JvGn27tLKYB2ZoXhoUbuCIoYa8e892hRoRB2xG4Jk\n"
                 "iU4A\n"
                 "-----END CERTIFICATE-----\n");
  X509_STORE_add_cert(v1, v2);
  return safe;
}
```



</details>


如遇技术问题，请按以下步骤排查：

1. **设备兼容性检查**
   - 确认设备型号为 OnePlus Ace5 Ultra
   - 验证 Android 版本与内核版本匹配

2. **数据安全措施**
   - 刷机前务必备份重要数据
   - 确保电池电量充足（建议 >50%）

3. **日志收集**
   - 保存日志
   - 记录错误信息

## 法律声明与免责条款

### 使用条款
- 本内核仅供技术学习和研究使用
- 用户需自行承担刷机风险
- 作者不对因使用本内核导致的设备问题负责
- 若有任何倒卖行为，则替开发者挡灾挡难

## 项目支持

如果您觉得这个项目对您有帮助，请考虑给予 Star ⭐ 支持项目发展。

对于技术问题和功能建议，欢迎通过 GitHub Issues 反馈。
