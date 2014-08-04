1. install the fake app (fake_adobe_flash_signed.apk)

2. open an app that has the embedded webview component and use the webview to open arbitrary URL

3. cat /proc/(victim_pid)/maps

You will see that the installed app has been loaded into the victim app's process space

--- Todo ---

To trigger the malicious code in the fake apk.

