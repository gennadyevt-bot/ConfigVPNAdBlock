package com.config.app

import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView

class DomainVpnActivity : AppCompatActivity() {

    private lateinit var rvDomains: RecyclerView
    private lateinit var etDomain: EditText
    private lateinit var btnAdd: Button
    private lateinit var btnSave: Button
    private lateinit var domainStorage: DomainVpnStorage
    private val domains = mutableListOf<String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_domain_vpn)
        applyReleaseInsets()

        domainStorage = DomainVpnStorage(this)
        domains.addAll(domainStorage.getDomains().sorted())

        rvDomains = findViewById(R.id.rvDomains)
        etDomain = findViewById(R.id.etDomain)
        btnAdd = findViewById(R.id.btnAdd)
        btnSave = findViewById(R.id.btnSave)

        rvDomains.layoutManager = LinearLayoutManager(this)
        rvDomains.adapter = DomainListAdapter(domains) { domain ->
            domainStorage.removeDomain(domain)
            domains.remove(domain)
            rvDomains.adapter?.notifyDataSetChanged()
        }

        btnAdd.setOnClickListener {
            val input = etDomain.text.toString().trim().lowercase()
            if (input.isEmpty()) {
                Toast.makeText(this, "Enter a domain", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val domain = input.removePrefix("https://").removePrefix("http://").removePrefix("www.").split("/")[0]
            if (domain.isEmpty() || domain.contains(" ")) {
                Toast.makeText(this, "Invalid domain", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            if (domains.contains(domain)) {
                Toast.makeText(this, "Domain already added", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            domainStorage.addDomain(domain)
            domains.add(domain)
            domains.sort()
            rvDomains.adapter?.notifyDataSetChanged()
            etDomain.text.clear()
            Toast.makeText(this, "Added: $domain", Toast.LENGTH_SHORT).show()
        }

        btnSave.setOnClickListener {
            val enabled = domains.isNotEmpty()
            if (enabled) {
                showAccessibilityDialog()
            } else {
                domainStorage.setEnabled(false)
                Toast.makeText(this, "Domain VPN disabled", Toast.LENGTH_SHORT).show()
                finish()
            }
        }
    }

    private fun showAccessibilityDialog() {
        AlertDialog.Builder(this)
            .setTitle("Доступ для Domain VPN")
            .setMessage("Config VPN использует Accessibility для чтения адресов сайтов, ссылок и текста на экране браузеров и Telegram, а также имени активного приложения. Эти данные обрабатываются на устройстве, чтобы автоматически включать VPN по вашим правилам; они не отправляются разработчику. Это дополнительная функция, не средство помощи людям с инвалидностью. Доступ можно отключить в настройках Android. Разрешить эту обработку и открыть настройки?")
            .setPositiveButton("Согласен") { _, _ ->
                domainStorage.setEnabled(true)
                startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
            }
            .setNegativeButton("Отмена", null)
            .show()
    }
}
