package com.example.qrcode
import android.content.Intent
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.core.view.isVisible
import com.budiyev.android.codescanner.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import org.json.JSONObject
import org.json.JSONArray
import java.io.IOException
 fun  rawJSON2(text: String ){
    GlobalScope.launch (Dispatchers.IO){

        val threatTypes = JSONArray()
        val platformTypes = JSONArray()
        val threatEntryTypes = JSONArray()
        val threatInfoItems = JSONObject()
        val threatEntries = JSONArray()
        val urlItem = JSONObject()
        val threatInfo = JSONObject()

        threatTypes.put("THREAT_TYPE_UNSPECIFIED")
        threatTypes.put("MALWARE")
        threatTypes.put("SOCIAL_ENGINEERING")
        threatTypes.put("UNWANTED_SOFTWARE")
        threatTypes.put("POTENTIALLY_HARMFUL_APPLICATION")

        threatEntryTypes.put("THREAT_ENTRY_TYPE_UNSPECIFIED")
        threatEntryTypes.put("URL")
        threatEntryTypes.put("EXECUTABLE")

        platformTypes.put("ANY_PLATFORM")
        urlItem.put("url", text)
        threatEntries.put(urlItem)

        threatInfoItems.put("threatTypes", threatTypes)
        threatInfoItems.put("platformTypes",platformTypes)
        threatInfoItems.put("threatEntryTypes",threatEntryTypes)
        threatInfoItems.put("threatEntries",threatEntries)
        threatInfo.put("threatInfo",threatInfoItems)

        val URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSyCDUw84JTjMCt96_wNJ7H_2l-oUoa0QxjU"
        val client = OkHttpClient()

        val requestBody = RequestBody.create(
            ("application/json").toMediaTypeOrNull(),
            threatInfo.toString()
        )

        val request = Request.Builder()
            .url(URL)
            .post(requestBody)
            .build()

        client.newCall(request).enqueue(object : Callback{

            override fun onFailure(call: Call, e: IOException) {
                e.printStackTrace()
                Log.i("mytag","fail to excecute")
            }

            override fun onResponse(call: Call, response: Response) {
                if(!response.isSuccessful){
                    Log.i("mytag","not successful")
                    Log.i("mytag", response.code.toString())
                    Log.i("mytag", response.message)
                } else{
                    val s = ""
                    val body = response?.body?.string()?:s
                    val safe = "{}\n"
                    if (body != null) {
                        Log.i("mytag",safe)
                        Log.i("mytag",body)
                        if (body == safe){
                            Log.i("mytag","safe")
                        } else{
                            Log.i("mytag","not safe")
                        }
                    }
                    else{
                        Log.i("mytag", "nothing")
                    }
                }

            }
        })
        Log.i("mytag","end connection12")
    }
}
class MainActivity : AppCompatActivity() {
    private lateinit var codeScanner: CodeScanner
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContentView(R.layout.activity_main)

        val scannerView = findViewById<CodeScannerView>(R.id.scanner_view)
        codeScanner = CodeScanner(this, scannerView)

        codeScanner.camera = CodeScanner.CAMERA_BACK // or CAMERA_FRONT or specific camera id
        codeScanner.formats = CodeScanner.ALL_FORMATS // list of type BarcodeFormat,
        codeScanner.autoFocusMode = AutoFocusMode.SAFE
        codeScanner.scanMode = ScanMode.SINGLE
        codeScanner.isAutoFocusEnabled = true // Whether to enable auto focus or not
        codeScanner.isFlashEnabled = false // Whether to enable flash or not

        // Callbacks
        codeScanner.decodeCallback = DecodeCallback {
            runOnUiThread {
                    GlobalScope.launch (Dispatchers.IO){

                        val threatTypes = JSONArray()
                        val platformTypes = JSONArray()
                        val threatEntryTypes = JSONArray()
                        val threatInfoItems = JSONObject()
                        val threatEntries = JSONArray()
                        val urlItem = JSONObject()
                        val threatInfo = JSONObject()

                        threatTypes.put("THREAT_TYPE_UNSPECIFIED")
                        threatTypes.put("MALWARE")
                        threatTypes.put("SOCIAL_ENGINEERING")
                        threatTypes.put("UNWANTED_SOFTWARE")
                        threatTypes.put("POTENTIALLY_HARMFUL_APPLICATION")

                        threatEntryTypes.put("THREAT_ENTRY_TYPE_UNSPECIFIED")
                        threatEntryTypes.put("URL")
                        threatEntryTypes.put("EXECUTABLE")

                        platformTypes.put("ANY_PLATFORM")
                        urlItem.put("url", it.text)
                        threatEntries.put(urlItem)

                        threatInfoItems.put("threatTypes", threatTypes)
                        threatInfoItems.put("platformTypes",platformTypes)
                        threatInfoItems.put("threatEntryTypes",threatEntryTypes)
                        threatInfoItems.put("threatEntries",threatEntries)
                        threatInfo.put("threatInfo",threatInfoItems)

                        val URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSyCDUw84JTjMCt96_wNJ7H_2l-oUoa0QxjU"
                        val client = OkHttpClient()

                        val requestBody = RequestBody.create(
                            ("application/json").toMediaTypeOrNull(),
                            threatInfo.toString()
                        )

                        val request = Request.Builder()
                            .url(URL)
                            .post(requestBody)
                            .build()

                        client.newCall(request).enqueue(object : Callback{

                            override fun onFailure(call: Call, e: IOException) {
                                e.printStackTrace()
                                Log.i("mytag","fail to excecute")
                            }

                            override fun onResponse(call: Call, response: Response) {
                                if(!response.isSuccessful){
                                    Log.i("mytag","not successful")
                                    Log.i("mytag", response.code.toString())
                                    Log.i("mytag", response.message)
                                } else{
                                    val s = ""
                                    val body = response?.body?.string()?:s
                                    val safe = "{}\n"
                                    if (body != null) {
                                        if (body == safe){
                                            Log.i("mytag","safe")
                                            /*val item = findViewById<TextView>(R.id.textID)
                                            item.text = it.text
                                            setContentView(R.layout.activity_scanned)*/
                                        } else{
                                            Log.i("mytag","not safe")
                                        }
                                    }
                                    else{
                                        Log.i("mytag", "nothing")
                                    }
                                }

                            }
                        })
                        Log.i("mytag","end connection12")
                    }

                Toast.makeText(this, "Scan result: ${it.text}", Toast.LENGTH_LONG).show()
            }
        }
        codeScanner.errorCallback = ErrorCallback {
            runOnUiThread {
                Toast.makeText(this, "Camera initialization error: ${it.message}",
                    Toast.LENGTH_LONG).show()
            }
        }

        scannerView.setOnClickListener {
            codeScanner.startPreview()
        }
    }

    override fun onResume() {
        super.onResume()
        codeScanner.startPreview()
    }

    override fun onPause() {
        codeScanner.releaseResources()
        super.onPause()
    }

}












































































































































































































































