import http.client
import json
from openpyxl import Workbook

# Virustotal API anahtarınızı buraya ekleyin
API_KEY = 'VT_API_KEY'

# SHA-256 değerlerinin listesi
sha256_hashes = [
    'SHA256 VALUE',
    # başka hash'ler eklenebilir
]

# Virustotal API URL
base_url = '/api/v3/files/'

# HTTP bağlantısı oluştur
conn = http.client.HTTPSConnection('www.virustotal.com')

# API isteği başlıkları
headers = {
    'x-apikey': API_KEY
}

# Excel dosyası için hazırlık
wb = Workbook()
ws = wb.active
ws.title = "VT Hash Results"
ws.append(["SHA256", "SHA1", "VT Skoru", "Popular Threat Label"])

# Her bir SHA-256 hash için API isteği gönder
for sha256_hash in sha256_hashes:
    url = f'{base_url}{sha256_hash}'
    conn.request("GET", url, headers=headers)
    response = conn.getresponse()
    data = response.read().decode('utf-8')

    sha1_hash = "N/A"
    vt_score = "N/A"
    threat_label = "N/A"

    if response.status == 200:
        json_data = json.loads(data)
        if 'data' in json_data:
            attributes = json_data['data']['attributes']
            sha1_hash = attributes.get('sha1', 'N/A')
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            vt_score = f"{malicious}/{total}"
            threat_label = attributes.get("popular_threat_classification", {}).get("suggested_threat_label", "N/A")
    else:
        print(f"{sha256_hash} -> Bulunamadı")

    ws.append([sha256_hash, sha1_hash, vt_score, threat_label])

# Bağlantıyı kapat
conn.close()

# Excel dosyasını kaydet
wb.save("vt_results.xlsx")
print("[+] vt_results.xlsx dosyası oluşturuldu.")
