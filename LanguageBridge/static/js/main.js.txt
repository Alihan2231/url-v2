// URL Security Scanner - Temel İşlevler

// Sayfa yüklendiğinde çalışacak fonksiyonlar
document.addEventListener('DOMContentLoaded', function() {
    // İstatistik grafiğini başlat (varsa)
    const chartCanvas = document.getElementById('scan-stats-chart');
    if (chartCanvas) {
        initScanResultChart();
    }
});

// İstatistik grafiği oluşturma fonksiyonu
function initScanResultChart() {
    const chartCanvas = document.getElementById('scan-stats-chart');
    const safeCount = parseInt(chartCanvas.getAttribute('data-safe') || 0);
    const unsafeCount = parseInt(chartCanvas.getAttribute('data-unsafe') || 0);
    
    const ctx = chartCanvas.getContext('2d');
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Güvenli URL\'ler', 'Tehlikeli URL\'ler'],
            datasets: [{
                data: [safeCount, unsafeCount],
                backgroundColor: ['#4CAF50', '#ef3340'],
                borderColor: ['#43A047', '#d12130'],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        font: {
                            family: "'Poppins', sans-serif",
                            size: 14,
                            weight: 500
                        },
                        color: '#f5f5f5'
                    }
                },
                title: {
                    display: true,
                    text: 'URL Tarama İstatistikleri',
                    font: {
                        family: "'Poppins', sans-serif",
                        size: 18,
                        weight: 700
                    },
                    color: '#f5f5f5',
                    padding: 20
                }
            }
        }
    });
}

// Panoya kopyalama fonksiyonu
function copyToClipboard(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    
    const toast = new bootstrap.Toast(document.getElementById('copy-toast'));
    toast.show();
}

// Raporu kopyalama fonksiyonu
function copyReport() {
    const url = document.getElementById('scanned-url')?.textContent || document.getElementById('scan-url')?.textContent;
    const status = document.getElementById('scan-status')?.textContent || document.getElementById('scan-result')?.textContent;
    const threats = document.getElementById('threat-types')?.textContent || 'Yok';
    const timestamp = document.getElementById('scan-timestamp').textContent;
    
    const reportText = `URL GÜVENLİK TARAMA RAPORU\n` +
                      `------------------------\n` +
                      `URL: ${url}\n` +
                      `Durum: ${status}\n` +
                      `Tehditler: ${threats}\n` +
                      `Tarih: ${timestamp}\n` +
                      `URL Güvenlik Tarayıcı ile kontrol edildi.`;
    
    copyToClipboard(reportText);
}
