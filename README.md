# resign-android-image

resign-android-image is a script that takes GrapheneOS binary OTA updates and resigns them with your own signing keys (including support for automating the process and installing in Qubes), and also supports applying modifications, such as having ADB root and being able to backup all applications, that violate the Android security model that GrapheneOS wishes to uphold, not because they make the device less secure for you, but because they follow your own wishes over providing guarantees to app developers that the OS will behave in a certain way. It could also support resigning stock Android 12 OS images with very few modifications.

With resign-android-image, you can take back control of your Android device, by letting you run the OS (currently only GrapheneOS is supported) with a locked bootloader, but signed with your own keys instead of the upstream keys, and with some optional modifications including optional root access, without building it from scratch every time there is an update.

With this tool, you are no longer at the mercy of your OS' upstream developers, and can decide for yourself how you want to configure your device without having to wipe /data and reinstall on every change, all without compromising the security of your own device by not locking the bootloader.

This tool works by resigning Android OS images with your own verified boot and APK keys and optionally making a few modifications by patching, such as enabling ADB root and removing a few antifeatures included in Android upstream. This is accomplished by partially reconstructing the target_files.zip from the upstream OTA updates, resigning and making changes, patching the file system images, and rebuilding OTA and/or factory images.

By resigning instead of rebuilding from scratch, you get an OS that is as close as possible to upstream, a much less resource-intensive process, and a much better guarantee that the process will not introduce bugs and once setup the system will continue working as the upstream OS is updated; furthermore, the way changes like ADB root is performed is much more minimal than existing options like a userdebug build and is thus very unlikely to introduce bugs or security holes unlike switching to an userdebug build.

In particular you can, without wiping /data:
- Change the way the OS is modified (e.g. to add/remove ADB root)
- Revert to an older OS version by signing it again (rollback prevention disallows this if you run with upstream keys, unless upstream agrees to resign an older version)
- Test your own OS modifications
- Gain ADB root and use it to arbitrarily read and modify the device state
- Switch to a different OS or a fork of your current OS in case you no longer like the way the OS you are running is being developed

This script is intended for personal use or internal use in an organization. You could also use this script to publish a fork of GrapheneOS, although in that case you should add support for replacing the OS name and logos to the script and use it, and also make sure to comply with all applicable copyright and trademark laws. Note that such a distribution will let users install it very easily, but they won't have the ability to run with a locked bootloader and full control of what OS runs on their device since they don't control the signing keys.

# Manual usage

`resign-android-image <work directory> <key directory> <os> <device> <build> [--ota] [--factory-image] [--factory-zip] <options>`

`<os>` is grapheneos, `<device>` is the device codename (only raven (Pixel 6 Pro) has been tested), `<build>` is the OTA version to modify.

The script is designed to run on Debian 11 and may work on Ubuntu and will most likely slight modifications for any other distribution; it should automatically download and install all dependencies. It can work incrementally and needs about 16GB (have 32GB free to be safe) of disk space and 15-30 minutes to do a full resign; 4GB of RAM is enough, but I'm not sure what the minimum RAM is.

Use --ota to generate an OTA, --factory-image to generate a factory image flashable payload, and --factory-zip to generate a factory image.

You can use --generate-keys to automatically generate keys if the key directory doesn't exist.

For debugging, use --keep to keep intermediate files and --keep-tmp to keep temporary files, --setx to show commands executed, --zip-opt 0 to speed up zipping during development.

Read the rest of this document and the source code of the script to find out the other options.

# Automatic update installation

This repository includes a script to setup a Qubes workstation that signs updates in a VM and either serves updates in another VM or uploads them via SSH to a VPS.

To use it:
1. Install Qubes on a supported machine if you don't already have a Qubes workstation
2. Install the Debian 11 OS template and create a Debian 11 based Qubes VM for signing updates
3. Create a Qubes VM for serving updates (or reuse another VM running servers) or get an VPS, cloud instance or remote server with SSH access
4. Setup a domain and point it to your Qubes workstation or SSH-accessible server (use a dynamic DNS updater if needed, for instance Cloudflare can provide dynamic DNS). Note that the update url including "https://" and a trailing slash must have the same number of characters as the OS update URL, which is "https://releases.grapheneos.org/" for GrapheneOS
5. Setup a web server in the server VM or SSH-accessible server with HTTPS certificates from letsencrypt (Caddy is recommended since it's written in a memory-safe language and easy to configure)
6. Clone this git repository in a trusted VM on the Qubes installation and copy the contents of this repository to dom0
7. Review the qubes-dom0-install script, modify it if desired and run it in dom0 as root, passing the options you want to pass to resign-android-image
8. Run the resigning script once manually in the signing VM with --generate-keys to generate keys, and follow the instructions to provide an otatools.zip and debug any issues
9. Enable and start the dom0 systemd timer that will automatically trigger updates, as instructed by the qubes-dom0-install script

If you don't want to use Qubes (note that having a secure workstation is crucial, which means not browsing the web or accessing untrusted data or running untrusted apps outside of dedicated VMs), read what qubes-dom0-install script does and mimic its behavior for your own setup.

# What could go wrong?

The situation to avoid is ending up in a state where there is no way to update the device via an OTA (you can't use fastboot with a locked bootloader), which can result in complete loss of data if the device also doesn't boot, and complete loss of non-root-accessible data if root is disabled.

Note that not locking the bootloader will make this situation impossible (you can always reflash from the bootloader), but at the cost of letting exploits be persistent, and evil maids replace your OS with impunity.

It would of course be ideal if Google had properly designed the Pixel devices and allowed fastboot flashing even with a locked bootloader (it's not clear why it's disabled since secure boot will just cause the device to fail to boot if you don't flash correctly signed data), but in practice it's probably quite unlikely that you will lock yourself out of the device like this.

On the other hand, if you can update the device with an OTA, you can just sign an update with ADB root enabled, or even root in the recovery and fix any issue using root privileges.

## Broken OTA updaters with no root

The main way that it could happen is if the OTA boots successfully (so the OS doesn't revert to the previous boot slot), but both the recovery and system updater don't work or have the wrong keys. To try to avoid this situation, this script will re-extract generated OTAs and factory images to make sure that the keys in otacerts.zip are correct. Having root enabled can provide an extra way of applying updates in this case. You may also be able to open the device and reprogram the UFS flash if you really need to.

## Key loss

If you lose your private keys, then of course it will be impossible to update the device since the bootloader is locked. Again, having root enabled will allow you to copy everything in /data and restore with no data loss at all (except for things protected with Keymaster keys, where you need to manually decrypt them until key escrow is implemented). Note that an hardware-based solution for this situation requires cracking the Titan M/M2 chip in addition to being able to reprogram the UFS flash.

# Modifications supported

## GrapheneOS updater URL

GrapheneOS designed the updater with an hardcoded update URL that it downloads updates from unconditionally; to remedy this, use --update-url to specify an alternate URL.

It works by binary patching resources.arsc in the updater APK.

Even with no options, the URL is replaced with an invalid domain to avoid performing useless downloads from the GrapheneOS official update server.

## ADB root

Not having full arbitrary read/write access to the state of your own device state is generally considered unacceptable and the sign of a device that is not truly yours and completely under your control, but rather owned and controlled by an entity who dictates how your device should behave; unfortunately that's the way it is with upstream GrapheneOS and stock OS, but fortunately, you can remedy the situation with the --adb-root option.

ADB root works in a minimally invasive way, by binary patching adbd so that all calls to __android_log_is_debuggable() are replaced with a constant of 1, making it believe that ro.debuggable=1 is set, even though it isn't (setting it globally like most Magisk and other rooting methods usually do causes several bugs since several parts of the system assume that functionality that is compiled out in non-debuggable builds is present when ro.debuggable=1).

ADB root also adds a SELinux policy extracted from a vanilla userdebug build to make the superuser permissive and also allow a bunch of other domains to interact with it (mostly to reply to requests made by the superuser). Note that this causes the policy to be built at boot instead of being prebuilt (probably adds 1 second of start up time) and removes the neverallow checks (they fail because the exclusions for su are compiled out, and fixing them is complicated); note that the neverallow checks do nothing at runtime and are merely a sanity check that already passes since otherwise the upstream OTA would have failed to build.

Note that no "su" binary is shipped.

Security impact: an exploit can potentially become persistent by enabling network ADB and whitelisting their own keys; exploits that somehow allow unauthorized ADB access will now give root to the attacker

## Ignore allowbackup and `<full-backup-content><exclude>`

The Android upstream OS contains antifeatures called "allowbackup=false" and "`<full-backup-content><exclude>`" that let application developers arbitrarily decide that the OS should not allow you to backup your own files that happen to be in the directory designated as their application's data directory.

By using --allowbackup, you can remedy the situation by making sure that the OS always ignores those decisions made against your interests. It works by making the already existing feature that only applies to apps targeting SDK >= 31 to all apps regardless of app version by patching the compat changes XML.

Unfortunately, the app is still allowed to exclude specific files from backup with `<data-extraction-rules><device-transfer><exclude>`, although hopefully that functionality will not be used. Currently there is no remedy for this, but root access can be used to access and modify the files freely, as it should be.

Security impact: attackers who gain access to the backup system will be able to extract more data, including data that app developers consider to be especially sensitive

## ADB backup

Recent Android upstream OS versions contain an antifeature that seeks to limit your access to your own data by disabling ADB backup for your own files that happen to be in directories designated as the data directory of an application targeting SDK >= 31.

By using --adb-backup, you can remedy the situation and disable this antifeature. It works by making it only apply to SDK >= 99 (which hopefully won't happen anytime soon) by patching the compat changes XML

Security impact: attackers who gain access to ADB will be able to extract more data, including data that app developers consider to be especially sensitive

## AdAway or custom hosts file

Android developers often release applications infested with advertisements for their own personal gain at your expense.

You can remedy this situation by enabling Private DNS and setting it to dns.adguard.com. If you don't like sending all you DNS requests to AdGuard, you can use --hosts-url URL or --adaway (which is --hosts-url https://adaway.org/hosts.txt) to replace the hosts file with one that can block a lot of advertising and tracking related domains.

Security impact: none affecting you

Functionality impact: you will not be able to access the blocked domains even if want to

## Magisk (manual)

You can install Magisk even though it's not recommended since it's not clear whether the Magisk author properly designed it in a secure way.

Currently, the only way is to use the standard install procedure, and then pass the patched boot.img to the script via --replace-boot

Security impact: unclear, depends on whether Magisk is properly engineered or not

# Modifications that would be nice to have - help wanted!

## Ignoring all backup-related manifest directives

Android OS contains an antifeature that lets applications tell the OS that you should not be allowed to backup specific files on your device that happen to be in the directory designated as their application's data directory.

Obviously, the OS should ignore such absurd requests instead and we should remedy the situation with a suitable modification.

This is currently not implemented, except for ignoring "allowbackup" as described above; in the meantime, ADB root can let you read and write those files.

## Recovery ADB shell and ADB root

ADB shell and ADB root in the recovery would be nice to have in case the device no longer boots enough to get to a normal ADB root.

Note however that this lets anyone with access to the device to gain root, so it's a good idea to only enable this when signing an OTA to recover an otherwise inaccessible device.

This is currently not implemented.

## Custom initialization scripts

While ADB root allows to perform occasional tasks as root, it would be nice to be able to specify arbitrary scripts and code to run at boot and potentially stay running all the time.

This is currently not implemented.

## Custom network provider

Android OS supports using a custom network provider, but only if it is among the ones that the upstream OS developers graciously permit the users to use.

It would be nice to remedy the situation and let the user choose any network provider regardless of the wishes of the upstream OS developers.

This would allow, for instance, to use the MicroG UnifiedNLP network provider.

This is currently not implemented.

## Location.isMock neutering

Android developers graciously included a freedom-respecting feature that allows you to instruct the OS to respond to location queries by asking an application of your choice that can respond arbitrarily rather than using the GPS receiver.

Unfortunately, they also included an antifeature, consisting in the "Location.isMock()" privacy-devastating interface, that disastrously leaks to applications information about whether you confidentially provided such an instruction the OS.

It would be nice to remedy the situation by always returning true to such impudent function calls.

This is currently not implemented.

## Screenshot disable ignoring

Android OS contains an antifeature that allows applications to disable taking a screenshot of your own device's screen when it happens to display graphical content provided by that application.

Obviously  such an absurd request should be completely disregarded.

This is currently not implemented.

## Screenshot detection prevention

Android OS stores screenshots as normal media, allowing application with the media permission to detect that a screenshot has been taken.

Obviously such a privacy hole should be plugged, by not treating screenshots as media unless/until the user shares them with an app.

This is currently not implemented.

## SafetyNet bypass (not yet without Magisk)

Google Play Services and Android-supporting hardware contain an antifeature called "SafetyNet" that lets third-parties require attestation that the hardware is running an OS version that abides by their dictates about how your device should work, rather than one that acts in your own interest and lets you choose how you want your own device to work (a form of treacherous computing - see https://www.gnu.org/philosophy/can-you-trust.en.html)

Unfortunately, the best that can be done is to pretend that your device is one not supporting hardware attestation and computing the software attestation so that it passes the check. In the future, this might be provided; the other alternatives are to proxy the request to a device running the stock OS (either a centralized device or one that needs to be bought by every user), or leveraging some sort of possibly hardware-based technique capable of extracting the attestation private keys from the hardware.

Currently no bypass for SafetyNet is included, the best solution is to modify the specific applications to remove the SafetyNet-related checks (if they aren't fully server-side) or failing that to install Magisk and enable the SafetyNet bypass module.

## Strongbox and TEE keymaster key escrow to yourself

Current Android hardware contains a dubious feature (mostly an antifeature, except for specialized uses) that lets applications store keys in your own TEE (TrustZone on main CPU) or Strongbox (Titan M/M2 on Pixels) in a way that doesn't let you extract them despite them being stored on your own device.

Among others, this means that a full copy of your device flash storage (even if at the unencrypted filesystem level) is not enough to read all the data and setup a new device to be in the same state as the old device, and in fact it makes it completely impossible to save the full state of a device since you can't read the keys.

The best solution seems to be to provide a modified HAL that also encrypts the keys to disk to a public key of your choice, allowing you to decrypt them on your secure workstation where the private key would be stored.

This would allow you to fully read the state of your device while still keeping the keys inaccessible without access to the master private key that is not stored on the device.

Currently this is not implemented yet.

## Signature spoofing

Android OS contains an antifeature that lets applications determine the key that they were signed with, and that prevents access to previous application data if you replace the application with one signed by a different key (such as your own key after having modified the application to remove some antifeature).

It would be nice to be able to remedy the situation by letting applications signed with the device releasekey (which is your own key when using this script) to specify an arbitrary key that they should appear to be signed as.

Currently this is not implemented yet, although we resign all system APKs so that you can later patch them without needing it.

At the moment you can use ADB root to save and restore the data across an application key change.

## Unaltered upstream OTA support

It would be nice to support updating with upstream OTAs without having to resign them, but it's major work and would significantly alter the way the system boots and updates.

This requires major work to write a custom "bootloader" (possibly a Linux kernel with kexec and custom initramfs) that would boot as a kernel and load the upstream kernel since we need to boot the upstream kernel (to support kernel updates) but we must use a modified initramfs (to support sideloading OTAs in recovery, which needs changed keys and changed update logic to not apply the vbmeta and rename the boot partitions from the upstream OTA).

This loader would need to cryptographically verify the vbmeta (including rollback protection, but it must be possible to "reset" it with an resign-android-image OTA) and load the kernel like the bootloader does with an initramfs modified on the fly to add hooks that make all the desired modifications dynamically.

The OTA update system also needs to be modified and must both support modified application of upstream OTAs plus application of resign-android-image OTAs.
