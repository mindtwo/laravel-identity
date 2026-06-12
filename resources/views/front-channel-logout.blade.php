<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    {{-- No-JS fallback; the embedded component performs the JS-driven redirect. --}}
    <meta http-equiv="refresh" content="8;url={{ $redirectUri ?? '/' }}">
    <title>Signing out…</title>
    <style>body{margin:0;padding:0;overflow:hidden;}</style>
</head>
<body>
<x-identity::front-channel-logout :urls="$iframeUrls" :redirect="$redirectUri ?? '/'" />
</body>
</html>
