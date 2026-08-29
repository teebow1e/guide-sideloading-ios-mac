# sign-decrypted-ipa.sh — resign & sideload an IPA

This repository contains a script to sign a **decrypted** IPA with your own Apple signing identity so it can be sideloaded onto a device. 

> Note: This guide requires you to have a MacOS device with Xcode installed.

## Requirements
- macOS with Xcode + Command Line Tools (`codesign`, `security`, `PlistBuddy`).
- `ios-deploy`: `brew install ios-deploy`.

## Guide
1. Make sure you have installed Xcode, after that launch Xcode and open Settings.

![alt text](/images/cls-2026-08-30-01.02.28.png)

2. Navigate to Apple Accounts and add your Apple account there:

![alt text](/images/cls-2026-08-30-01.03.31.png)

After finish, it should look like this:

![alt text](/images/cls-2026-08-30-01.04.08.png)

3. Create a project in Xcode. Note that you can name the Product Name and the Organization Identifier anything you want.
> Note: the side effect of this is that the IPA will be installed with this identifier, not the app's expected identifier. For example, Apollo Reborn has the original identifier `com.christianselig.Apollo`, if you sign with this guide, it will be named under the name you chosen.

![alt text](/images/cls-2026-08-30-01.06.57.png)

4. Xcode will launch, at this stage, you should got your phone plugged in.

![alt text](/images/cls-2026-08-30-01.07.45.png)

5. Click as in the photo, then choose the team that's available. This should show your Apple ID:

![alt text](/images/cls-2026-08-30-01.09.25.png)

![alt text](/images/cls-2026-08-30-01.10.04.png)

![alt text](/images/cls-2026-08-30-01.10.23.png)

At this point, you can close Xcode.

6. Launch sign-decrypted-ipa.sh
> Note: If you do not trust my script, you can feed it to any virus-scanning tool like VirusTotal or ask an AI assistant to analyze it.

```bash
./sign-decrypted-ipa.sh <input.ipa> --install
```

At this step, it should automatically run, but I have several projects so I just select the newly created one then press Enter:

![alt text](/images/cls-2026-08-30-01.19.11.png)

Now just wait:
![alt text](/images/cls-2026-08-30-01.12.34.png)