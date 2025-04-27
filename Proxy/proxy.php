<?php
// ==== تنظیمات ====
$baseUrl = "https://uiapi.saapa.ir";
$logFile = __DIR__ . "/proxy.log";
$timeout = 60; // زمان انتظار به ثانیه

// ==== مسیر نهایی ====
$path = $_SERVER['REQUEST_URI'];
$proxyPath = preg_replace("/^\/proxy\.php/", '', $path);
$targetUrl = $baseUrl . $proxyPath;

// ==== لاگ درخواست ====
logMessage("REQUEST", [
    "method" => $_SERVER['REQUEST_METHOD'],
    "path" => $path,
    "targetUrl" => $targetUrl,
    "time" => date("Y-m-d H:i:s")
]);

// ==== خواندن اطلاعات درخواست ====
$headers = getallheaders();
$body = file_get_contents("php://input");

// ==== آماده‌سازی هدرها ====
$forwardHeaders = [];
foreach ($headers as $key => $value) {
    $keyLower = strtolower($key);
    if ($keyLower === "host") continue;
    // حفظ هدر Accept-Encoding اصلی
    if ($keyLower !== "accept-encoding") {
        $forwardHeaders[$key] = $value;
    }
}

// ==== ساخت کانتکست برای ارسال با cURL ====
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $targetUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $_SERVER['REQUEST_METHOD']);

// تنظیم هدرها
$curlHeaders = [];
foreach ($forwardHeaders as $key => $value) {
    $curlHeaders[] = "$key: $value";
}
curl_setopt($ch, CURLOPT_HTTPHEADER, $curlHeaders);

// تنظیم داده‌های ارسالی
if ($_SERVER['REQUEST_METHOD'] === 'POST' || $_SERVER['REQUEST_METHOD'] === 'PUT') {
    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
}

// گرفتن هدرهای پاسخ
curl_setopt($ch, CURLOPT_HEADERFUNCTION, function($curl, $header) use (&$responseHeaders) {
    $len = strlen($header);
    $header = explode(':', $header, 2);
    if (count($header) < 2) // خطوط هدر بدون مقدار را رد کن
        return $len;

    $name = trim($header[0]);
    $value = trim($header[1]);
    $responseHeaders[$name] = $value;
    
    return $len;
});

// ==== ارسال و دریافت پاسخ ====
$response = curl_exec($ch);
$httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$error = curl_error($ch);
$errno = curl_errno($ch);
$info = curl_getinfo($ch);

// لاگ اطلاعات پاسخ
logMessage("RESPONSE", [
    "code" => $httpcode,
    "error" => $error,
    "errno" => $errno,
    "url" => $targetUrl,
    "time_taken" => $info['total_time'],
    "response_size" => strlen($response),
    "time" => date("Y-m-d H:i:s")
]);

// بررسی خطاها
if ($errno) {
    http_response_code(500);
    echo json_encode([
        "error" => "خطا در ارسال درخواست به مقصد: $error",
        "code" => $errno
    ]);
    curl_close($ch);
    exit;
}

// ==== ارسال هدرهای پاسخ ====
http_response_code($httpcode);
foreach ($responseHeaders as $name => $value) {
    header("$name: $value");
}

// ==== خروجی نهایی ====
echo $response;
curl_close($ch);

// ==== تابع لاگ ساده ====
function logMessage(string $type, array $data): void
{
    global $logFile;
    $log = "[" . date("Y-m-d H:i:s") . " - $type]\n";
    foreach ($data as $key => $value) {
        $log .= $key . ": " . (is_array($value) ? json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) : $value) . "\n";
    }
    $log .= "[END $type]\n\n";
    file_put_contents($logFile, $log, FILE_APPEND);
}