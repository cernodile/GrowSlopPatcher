package org.gtmodloader.sloppatcher

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import com.android.apksig.ApkSigner
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.jf.baksmali.Baksmali
import org.jf.baksmali.BaksmaliOptions
import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcodes
import org.jf.smali.Smali
import org.jf.smali.SmaliOptions
import java.io.*
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.util.*
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

object ModProcessor {

    init {
        Security.removeProvider("BC")
        Security.addProvider(BouncyCastleProvider())
    }

    private class CountingOutputStream(out: OutputStream) : FilterOutputStream(out) {
        private var count: Long = 0
        override fun write(b: Int) {
            out.write(b)
            count++
        }
        override fun write(b: ByteArray, off: Int, len: Int) {
            out.write(b, off, len)
            count += len.toLong()
        }
        fun getCount(): Long = count
    }

    fun process(
        context: Context,
        apkUri: Uri,
        soUri: Uri,
        soFileName: String,
        iconUri: Uri?,
        onProgress: (String) -> Unit,
        onComplete: (File) -> Unit,
        onError: (Exception) -> Unit
    ) {
        Thread {
            try {
                val workDir = File(context.cacheDir, "mod_work").apply {
                    deleteRecursively()
                    mkdirs()
                }
                val originalApk = File(workDir, "original.apk")
                val outputApk = File(workDir, "modified_unsigned.apk")
                val signedApk = File(context.getExternalFilesDir(null), "modded_app.apk")

                val libName = soFileName.substring(3, soFileName.length - 3)

                // 1. Copy APK to work dir
                onProgress("Copying APK...")
                context.contentResolver.openInputStream(apkUri)?.use { input ->
                    originalApk.outputStream().use { output -> input.copyTo(output) }
                }

                // 2. Extract classes.dex
                onProgress("Extracting classes.dex...")
                val dexFile = File(workDir, "classes.dex")
                ZipInputStream(originalApk.inputStream()).use { zis ->
                    var entry = zis.nextEntry
                    while (entry != null) {
                        if (entry.name == "classes.dex") {
                            dexFile.outputStream().use { zis.copyTo(it) }
                            break
                        }
                        entry = zis.nextEntry
                    }
                }

                if (!dexFile.exists()) throw Exception("classes.dex not found in APK")

                // 3. Decompile DEX to Smali
                onProgress("Decompiling DEX...")
                val smaliDir = File(workDir, "smali")
                val dexFileObj = DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault())
                val baksmaliOptions = BaksmaliOptions()
                baksmaliOptions.apiLevel = 24
                Baksmali.disassembleDexFile(dexFileObj, smaliDir, Runtime.getRuntime().availableProcessors(), baksmaliOptions)

                // 4. Modify Smali
                onProgress("Modifying Smali...")
                val mainSmaliFile = File(smaliDir, "com/rtsoft/growtopia/Main.smali")
                if (mainSmaliFile.exists()) {
                    var content = mainSmaliFile.readText()
                    if (!content.contains("invoke-static {v2}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V")) {
                        val target = "sget-object v0, Lcom/rtsoft/growtopia/Main;->dllname:Ljava/lang/String;"
                        val patch = """
                            |    const-string v2, "$libName"
                            |
                            |    invoke-static {v2}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
                            |
                            |    sget-object v0, Lcom/rtsoft/growtopia/Main;->dllname:Ljava/lang/String;
                        """.trimMargin()

                        if (content.contains(target)) {
                            content = content.replace(target, patch)
                            mainSmaliFile.writeText(content)
                        } else {
                            onProgress("Warning: Target signature not found in Main.smali")
                        }
                    } else {
                        onProgress("Main.smali already patched, skipping.")
                    }
                } else {
                    onProgress("Warning: Main.smali not found at expected path.")
                }

                // 5. Recompile Smali to DEX
                onProgress("Recompiling Smali...")
                val modifiedDex = File(workDir, "classes_mod.dex")
                val smaliOptions = SmaliOptions()
                smaliOptions.outputDexFile = modifiedDex.absolutePath
                smaliOptions.apiLevel = 24
                smaliOptions.jobs = Runtime.getRuntime().availableProcessors()

                if (!Smali.assemble(smaliOptions, smaliDir.absolutePath)) {
                    throw Exception("Smali assembly failed")
                }

                // 6. Rebuild APK
                onProgress("Rebuilding APK...")
                val userIconBitmap = iconUri?.let { uri ->
                    context.contentResolver.openInputStream(uri)?.use {
                        BitmapFactory.decodeStream(it)
                    }
                }

                val cos = CountingOutputStream(BufferedOutputStream(outputApk.outputStream()))
                ZipOutputStream(cos).use { zos ->
                    var foundAndReplacedLibrary = false
                    ZipInputStream(BufferedInputStream(originalApk.inputStream())).use { zis ->
                        var entry = zis.nextEntry
                        while (entry != null) {
                            val name = entry.name

                            // Check if this is an icon file we want to replace
                            val isIcon = userIconBitmap != null && name.contains("icon.png")

                            if (name != "classes.dex" && !name.startsWith("META-INF/") && !isIcon) {
                                if (name == "resources.arsc" || name.endsWith(".so")) {
                                    val bytes = zis.readBytes()
                                    val newEntry = ZipEntry(name)
                                    newEntry.method = ZipEntry.STORED
                                    newEntry.size = bytes.size.toLong()
                                    newEntry.compressedSize = bytes.size.toLong()
                                    val crc = CRC32()
                                    crc.update(bytes)
                                    newEntry.crc = crc.value

                                    val currentPos = cos.getCount()
                                    val padding = (4 - (currentPos + 30 + name.length) % 4) % 4
                                    if (padding > 0) {
                                        newEntry.extra = ByteArray(padding.toInt())
                                    }

                                    zos.putNextEntry(newEntry)
                                    zos.write(bytes)

                                    if (name.endsWith(soFileName)) {
                                        onProgress("Added .so file...")
                                        foundAndReplacedLibrary = true
                                    }
                                } else {
                                    zos.putNextEntry(ZipEntry(name))
                                    zis.copyTo(zos)
                                }
                                zos.closeEntry()
                            } else if (isIcon && userIconBitmap != null) {
                                // Replace icon with resized version
                                val originalBytes = zis.readBytes()
                                val options = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                                BitmapFactory.decodeByteArray(originalBytes, 0, originalBytes.size, options)

                                val targetWidth = options.outWidth
                                val targetHeight = options.outHeight

                                val resizedBytes = if (targetWidth > 0 && targetHeight > 0) {
                                    val format = if (name.endsWith(".webp")) Bitmap.CompressFormat.WEBP else Bitmap.CompressFormat.PNG
                                    val out = ByteArrayOutputStream()
                                    val scaledBitmap = Bitmap.createScaledBitmap(userIconBitmap, targetWidth, targetHeight, true)
                                    scaledBitmap.compress(format, 100, out)
                                    if (scaledBitmap != userIconBitmap) scaledBitmap.recycle()
                                    out.toByteArray()
                                } else {
                                    originalBytes // Keep original if we can't determine size
                                }

                                val newEntry = ZipEntry(name)
                                zos.putNextEntry(newEntry)
                                zos.write(resizedBytes)
                                zos.closeEntry()
                            }
                            entry = zis.nextEntry
                        }
                    }
                    userIconBitmap?.recycle()

                    zos.putNextEntry(ZipEntry("classes.dex"))
                    modifiedDex.inputStream().use { it.copyTo(zos) }
                    zos.closeEntry()

                    if (!foundAndReplacedLibrary) {
                        onProgress("Adding .so file...")
                        val soInputStream = context.contentResolver.openInputStream(soUri)
                            ?: throw Exception("Cannot open .so URI")
                        val soBytes = soInputStream.use { it.readBytes() }
                        val soEntry = ZipEntry("lib/arm64-v8a/$soFileName")
                        soEntry.method = ZipEntry.STORED
                        soEntry.size = soBytes.size.toLong()
                        soEntry.compressedSize = soBytes.size.toLong()
                        val crc = CRC32()
                        crc.update(soBytes)
                        soEntry.crc = crc.value

                        val currentPos = cos.getCount()
                        val padding = (4 - (currentPos + 30 + soEntry.name.length) % 4) % 4
                        if (padding > 0) {
                            soEntry.extra = ByteArray(padding.toInt())
                        }

                        zos.putNextEntry(soEntry)
                        zos.write(soBytes)
                        zos.closeEntry()
                    }
                }

                // 7. Sign APK
                onProgress("Signing APK...")
                signApk(context, outputApk, signedApk)

                onProgress("Process Complete!")
                onComplete(signedApk)

            } catch (e: Exception) {
                onError(e)
            }
        }.start()
    }

    private fun signApk(context: Context, input: File, output: File) {
        val keystoreFile = File(context.filesDir, "growmodder.p12")
        val (privateKey, cert) = if (keystoreFile.exists()) {
            loadKeyFromStorage(keystoreFile)
        } else {
            generateAndSaveKey(keystoreFile)
        }

        val signerConfig = ApkSigner.SignerConfig.Builder(
            "growmodder",
            privateKey,
            listOf(cert)
        ).build()

        ApkSigner.Builder(listOf(signerConfig))
            .setInputApk(input)
            .setOutputApk(output)
            .setV1SigningEnabled(true)
            .setV2SigningEnabled(true)
            .setV3SigningEnabled(true)
            .setV4SigningEnabled(false)
            .build()
            .sign()
    }

    private fun generateAndSaveKey(file: File): Pair<PrivateKey, X509Certificate> {
        // 1. Generate KeyPair and Certificate
        val keyPairGen = KeyPairGenerator.getInstance("RSA", "BC")
        keyPairGen.initialize(2048)
        val keyPair = keyPairGen.generateKeyPair()
        val cert = generateCertificate(keyPair)

        // 2. Create and Save Keystore
        val keyStore = KeyStore.getInstance("PKCS12")
        keyStore.load(null, null)
        keyStore.setKeyEntry("growmodder", keyPair.private, "insecure!".toCharArray(), arrayOf(cert))

        file.outputStream().use { fos ->
            keyStore.store(fos, "insecure!".toCharArray())
        }

        return Pair(keyPair.private, cert)
    }

    private fun loadKeyFromStorage(file: File): Pair<PrivateKey, X509Certificate> {
        val keyStore = KeyStore.getInstance("PKCS12")
        file.inputStream().use { fis ->
            keyStore.load(fis, "insecure!".toCharArray())
        }

        val privateKey = keyStore.getKey("growmodder", "insecure!".toCharArray()) as PrivateKey
        val cert = keyStore.getCertificate("growmodder") as X509Certificate
        return Pair(privateKey, cert)
    }

    private fun generateCertificate(keyPair: KeyPair): X509Certificate {
        val owner = X500Name("CN=GrowModder")
        val serial = BigInteger.valueOf(System.currentTimeMillis())
        val notBefore = Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24)
        val notAfter = Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365 * 10)

        val certBuilder = JcaX509v3CertificateBuilder(
            owner, serial, notBefore, notAfter, owner, keyPair.public
        )

        val signer = JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.private)
        return JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer))
    }
}
