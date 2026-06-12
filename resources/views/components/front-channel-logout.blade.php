{{--
    Front-channel logout mechanism (OpenID Connect Front-Channel Logout 1.0).

    Loads one hidden iframe per RP logout URI so each RP can clear its session,
    then continues to $redirect once they have all loaded (or after a timeout).

    Embed it inside your own page to apply your branding without reimplementing
    the logic:  <x-identity::front-channel-logout :urls="$iframeUrls" :redirect="$redirectUri" />

    @param list<string> $urls     RP front-channel logout iframe URLs
    @param string       $redirect Where to send the browser once logout completes
--}}
@props(['urls' => [], 'redirect' => '/'])

<script>
    (function () {
        var remaining = {{ count($urls) }};
        var redirectUri = {{ Js::from($redirect) }};

        function go() { window.location.href = redirectUri; }

        if (remaining === 0) {
            go();
        } else {
            // Fall back to a timeout in case an RP iframe never fires onload.
            var timer = setTimeout(go, 5000);

            window.identityFrontChannelDone = function () {
                if (--remaining <= 0) {
                    clearTimeout(timer);
                    go();
                }
            };
        }
    })();
</script>

@foreach ($urls as $url)
    <iframe src="{{ $url }}"
            width="0"
            height="0"
            style="display:none;"
            referrerpolicy="no-referrer"
            sandbox
            onload="identityFrontChannelDone()"></iframe>
@endforeach
