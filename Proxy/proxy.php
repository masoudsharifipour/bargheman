<?php
// ==== تنظیمات ====
$baseUrl = "https://uiapi.saapa.ir";
$logFile = __DIR__ . "/proxy.log";
$timeout = 60; // زمان انتظار به ثانیه

// ==== مسیر نهایی ====
$path = $_SERVER['REQUEST_URI'];
$proxyPath = preg_replace("/^\/proxy\.php/", '', $path);
$targetUrl = $baseUrl . $proxyPath;



// ==== خواندن اطلاعات درخواست ====
$headers = getallheaders();
$bodyContent = file_get_contents("php://input");
$body = $bodyContent; // برای استفاده در cURL
// 

// ==== لاگ درخواست ====
logMessage("REQUEST", [
    "method" => $_SERVER['REQUEST_METHOD'],
    "path" => $path,
    "targetUrl" => $targetUrl,
    "headers" => $headers,
    "body_raw" => $bodyContent,
    "time" => date("Y-m-d H:i:s")
]);


// ==== آماده‌سازی هدرها ====
$forwardHeaders = [];
foreach ($headers as $key => $value) {
    $keyLower = strtolower($key);
    if ($keyLower === "host")
        continue;
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
curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($curl, $header) use (&$responseHeaders) {
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
    "headers" => $responseHeaders,
    "body_raw" => $response,
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
// ==== تابع لاگ پیشرفته نهایی ====
function logMessage(string $type, array $data): void
{
    global $logFile;

    $log = "[" . date("Y-m-d H:i:s") . " - $type]\n";

    // اطلاعات کاربر
    $log .= "ip: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . "\n";
    $log .= "user_agent: " . ($_SERVER['HTTP_USER_AGENT'] ?? 'unknown') . "\n";

    // اگر Authorization هست
    $headers = $data['headers'] ?? [];
    if (isset($headers['Authorization'])) {
        $log .= "authorization: " . $headers['Authorization'] . "\n";
    }

    // اگر body_raw هست و JSON قابل پارس بود، payload رو جداگانه لاگ کن
    if (isset($data['body_raw'])) {
        $bodyRaw = $data['body_raw'];
        $bodyJson = json_decode($bodyRaw, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            $log .= "payload: " . json_encode($bodyJson, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";

            if (isset($bodyJson['SessionKey'])) {
                $log .= "session_key: " . $bodyJson['SessionKey'] . "\n";
            }
        } else {
            $log .= "body_raw: $bodyRaw\n";
        }
        unset($data['body_raw']); // دیگه لاگ نشه جداگانه
    }  

    // لاگ سایر کلیدها
    foreach ($data as $key => $value) {
        if ($key === 'headers')
            continue; // چون جدا لاگ کردیم
        $log .= "$key: " . (is_array($value) ? json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) : $value) . "\n";
    }

    $log .= "[END $type]\n\n";
    file_put_contents($logFile, $log, FILE_APPEND);
}