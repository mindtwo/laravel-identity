<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="8;url={{ $redirectUri ?? '/' }}">
    <title>Signing out…</title>
    <style>body{margin:0;padding:0;overflow:hidden;}</style>
</head>
<body>
@foreach ($iframeUrls as $url)
    <iframe src="{{ $url }}"
            width="0"
            height="0"
            style="display:none;"
            referrerpolicy="no-referrer"
            sandbox
            onload="done()"></iframe>
@endforeach

<script>
    var remaining = {{ count($iframeUrls) }};
    var redirectUri = {{ Js::from($redirectUri ?? '/') }};
    var timer = setTimeout(function () { window.location.href = redirectUri; }, 5000);
    function done() {
        remaining -= 1;
        if (remaining <= 0) {
            clearTimeout(timer);
            window.location.href = redirectUri;
        }
    }
</script>
</body>
</html>
