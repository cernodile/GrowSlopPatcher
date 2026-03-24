package org.gtmodloader.sloppatcher

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import org.gtmodloader.sloppatcher.ui.theme.GrowModderTheme
import java.io.File
import java.util.zip.ZipInputStream

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            GrowModderTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    FilePickerScreen(modifier = Modifier.padding(innerPadding))
                }
            }
        }
    }
}

data class ApkInfo(val version: String?, val architectures: List<String>, val packageName: String?)

fun getApkInfo(context: Context, uri: Uri): ApkInfo {
    var version: String? = null
    var name: String? = null
    val architectures = mutableListOf<String>()

    try {
        val tempFile = File.createTempFile("temp_apk", ".apk", context.cacheDir)
        context.contentResolver.openInputStream(uri)?.use { input ->
            tempFile.outputStream().use { output ->
                input.copyTo(output)
            }
        }
        
        val packageInfo: PackageInfo? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.packageManager.getPackageArchiveInfo(
                tempFile.absolutePath,
                android.content.pm.PackageManager.PackageInfoFlags.of(0)
            )
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageArchiveInfo(tempFile.absolutePath, 0)
        }
        
        version = packageInfo?.versionName
        name = packageInfo?.packageName
        tempFile.delete()
    } catch (e: Exception) {
        e.printStackTrace()
    }

    try {
        context.contentResolver.openInputStream(uri)?.use { input ->
            ZipInputStream(input).use { zip ->
                var entry = zip.nextEntry
                while (entry != null) {
                    if (entry.name.startsWith("lib/")) {
                        val parts = entry.name.split("/")
                        if (parts.size >= 3) {
                            val arch = parts[1]
                            if (arch !in architectures) {
                                architectures.add(arch)
                            }
                        }
                    }
                    entry = zip.nextEntry
                }
            }
        }
    } catch (e: Exception) {
        e.printStackTrace()
    }

    return ApkInfo(version, architectures, name)
}

fun isElfFile(context: Context, uri: Uri): Boolean {
    return try {
        context.contentResolver.openInputStream(uri)?.use { input ->
            val buffer = ByteArray(4)
            val read = input.read(buffer)
            if (read == 4) {
                buffer[0] == 0x7F.toByte() &&
                        buffer[1] == 'E'.toByte() &&
                        buffer[2] == 'L'.toByte() &&
                        buffer[3] == 'F'.toByte()
            } else false
        } ?: false
    } catch (e: Exception) {
        false
    }
}

fun getFileName(context: Context, uri: Uri): String? {
    var result: String? = null
    if (uri.scheme == "content") {
        val cursor = context.contentResolver.query(uri, null, null, null, null)
        try {
            if (cursor != null && cursor.moveToFirst()) {
                val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (index != -1) {
                    result = cursor.getString(index)
                }
            }
        } finally {
            cursor?.close()
        }
    }
    if (result == null) {
        result = uri.path
        val cut = result?.lastIndexOf('/')
        if (cut != null && cut != -1) {
            result = result?.substring(cut + 1)
        }
    }
    return result
}

fun installApk(context: Context, apkFile: File) {
    val apkUri = FileProvider.getUriForFile(
        context,
        "${context.packageName}.fileprovider",
        apkFile
    )
    val intent = Intent(Intent.ACTION_VIEW).apply {
        setDataAndType(apkUri, "application/vnd.android.package-archive")
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    context.startActivity(intent)
}

@Composable
fun FilePickerScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    var apkUri by remember { mutableStateOf<Uri?>(null) }
    var soUri by remember { mutableStateOf<Uri?>(null) }
    var iconUri by remember { mutableStateOf<Uri?>(null) }
    var soFileName by remember { mutableStateOf<String?>(null) }
    var customPackageName by remember { mutableStateOf("") }
    var appVisualName by remember { mutableStateOf("Growtopia") }
    var apkInfo by remember { mutableStateOf<ApkInfo?>(null) }
    var isSoValid by remember { mutableStateOf(false) }

    var isProcessing by remember { mutableStateOf(false) }
    var progressMessage by remember { mutableStateOf("") }
    var resultApkFile by remember { mutableStateOf<File?>(null) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    val apkPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        apkUri = uri
        uri?.let {
            apkInfo = getApkInfo(context, it)
        }
    }

    val soPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        soUri = uri
        if (uri != null) {
            val fileName = getFileName(context, uri)
            soFileName = fileName
            val startsWithLib = fileName?.startsWith("lib") ?: false
            val isElf = isElfFile(context, uri)
            isSoValid = startsWithLib && isElf
            
            if (!startsWithLib) {
                errorMessage = "Selected file name must start with 'lib'"
            } else if (!isElf) {
                errorMessage = "Selected file is not a valid .so (ELF) file"
            } else {
                errorMessage = null
                // Default package name
                val baseName = fileName?.removePrefix("lib")?.removeSuffix(".so") ?: ""
                if (customPackageName.isEmpty() || customPackageName.startsWith("com.rtsoft.growtopia.")) {
                    customPackageName = "com.rtsoft.growtopia.$baseName"
                }
            }
        } else {
            isSoValid = false
            soFileName = null
        }
    }

    val iconPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        iconUri = uri
    }

    val saveApkLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/vnd.android.package-archive")
    ) { uri: Uri? ->
        uri?.let {
            try {
                context.contentResolver.openOutputStream(it)?.use { outputStream ->
                    resultApkFile?.inputStream()?.use { inputStream ->
                        inputStream.copyTo(outputStream)
                    }
                }
                Toast.makeText(context, "APK saved successfully", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                errorMessage = "Failed to save APK: ${e.message}"
            }
        }
    }

    val isApkValid = apkInfo?.let {
        it.architectures.contains("arm64-v8a") && it.packageName == "com.rtsoft.growtopia"
    } ?: false

    val scrollState = rememberScrollState()

    Column(
        modifier = modifier.fillMaxSize().padding(16.dp).verticalScroll(scrollState),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "GrowModder",
            style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.padding(bottom = 32.dp)
        )

        if (isProcessing) {
            CircularProgressIndicator()
            Spacer(modifier = Modifier.height(16.dp))
            Text(text = progressMessage)
        } else if (resultApkFile != null) {
            Text(text = "✅ Modification Complete!", color = MaterialTheme.colorScheme.primary)
            Spacer(modifier = Modifier.height(16.dp))
            
            Button(
                onClick = { installApk(context, resultApkFile!!) },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Install Modified APK")
            }
            
            Spacer(modifier = Modifier.height(8.dp))
            
            Button(
                onClick = { saveApkLauncher.launch("growtopia_modded.apk") },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Save Modified APK")
            }
            
            Spacer(modifier = Modifier.height(16.dp))

            TextButton(onClick = { resultApkFile = null }) {
                Text("Start Over")
            }
        } else {
            Button(
                onClick = { apkPickerLauncher.launch("application/vnd.android.package-archive") },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(text = if (apkUri == null) "Select APK File" else "APK Selected")
            }

            apkInfo?.let {
                Column(modifier = Modifier.padding(top = 8.dp)) {
                    Text("Detected Version: ${it.version ?: "Unknown"}", style = MaterialTheme.typography.bodySmall)
                    Text("Detected Archs: ${it.architectures.joinToString()}", style = MaterialTheme.typography.bodySmall)
                    
                    if (isApkValid) {
                        Text("APK is valid", color = MaterialTheme.colorScheme.primary)
                    } else {
                        Text("❌ APK mismatch (Expected an ARM64 com.rtsoft.growtopia APK)", color = MaterialTheme.colorScheme.error)
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = { soPickerLauncher.launch("*/*") },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(text = if (soUri == null) "Select .so File" else ".so Selected")
            }
            soUri?.let {
                Column(modifier = Modifier.padding(top = 4.dp)) {
                    Text(
                        text = soFileName ?: "Selected",
                        style = MaterialTheme.typography.bodySmall
                    )
                    if (isSoValid) {
                        Text("Valid ELF binary", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodySmall)
                    } else {
                        Text("❌ Invalid file", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            OutlinedTextField(
                value = customPackageName,
                onValueChange = { customPackageName = it },
                label = { Text("Package Name (Optional)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Spacer(modifier = Modifier.height(24.dp))

            OutlinedTextField(
                value = appVisualName,
                onValueChange = { appVisualName = it },
                label = { Text("App Name") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = { iconPickerLauncher.launch("image/*") },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(text = if (iconUri == null) "Select New App Icon (Optional)" else "Icon Selected")
            }
            iconUri?.let {
                Text(
                    text = getFileName(context, it) ?: "Selected",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }

            errorMessage?.let {
                Spacer(modifier = Modifier.height(16.dp))
                Text(text = it, color = MaterialTheme.colorScheme.error)
            }

            if (apkUri != null && soUri != null && isApkValid && isSoValid) {
                Spacer(modifier = Modifier.height(48.dp))
                Button(onClick = {
                    isProcessing = true
                    errorMessage = null
                    ModProcessor.process(
                        context = context,
                        apkUri = apkUri!!,
                        soUri = soUri!!,
                        soFileName = soFileName!!,
                        appName = appVisualName,
                        targetPackageName = customPackageName,
                        iconUri = iconUri,
                        onProgress = { progressMessage = it },
                        onComplete = { file ->
                            isProcessing = false
                            resultApkFile = file
                        },
                        onError = { e ->
                            isProcessing = false
                            errorMessage = "Error: ${e.message}"
                        }
                    )
                }) {
                    Text("Patch APK")
                }
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun FilePickerPreview() {
    GrowModderTheme {
        FilePickerScreen()
    }
}
