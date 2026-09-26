# resign-android-image

**Status: minimally maintained for my own Pixel 6 Pro and Pixel Tablet, other devices completely untested by me. Added some code to support Pixel 7/8/..., it builds but not sure if it actually works. Currently working with Android 17 builds including both OTA and installation on new devices; it should continue working including with new Android versions until major modifications to the build or OS layout are made**

**Important: when setting up GrapheneOS, make sure to select to NOT disable OEM unlocking (disabling it is currently the default, so you need to uncheck the checkbox explicitly!), unless you REALLY know what you are doing! Doing so means that you can get the device in a state where it doesn't boot, doesn't enter recovery, you can't flash with fastboot and you can't unlock the bootloader to flash, which might make the device unrecoverable. While I never bricked my own device, this script is not as reliable as the main GrapheneOS build infrastructure.** Note that the downside is large, but the security benefit is very limited or nonexistent. Someone who manages to get kernel-level or root-level access remotely to a device or someone with physical access to an unlocked device can just turn it on again, while someone with physical access to a locked device can just replace the device with an identical device, achieving the same result as unlocking the bootloader on your device, since it wipes user data anyway. Since data is wiped, you will notice it and can check the key ID during boot to see if the bootloader was unlocked or relocked with a different key. Anyone will physical access will be able to easily wipe your device and data at no cost if you leave OEM unlocking enabled, but stealing it or hitting it with an hammer also causes you to lose the data.

resign-android-image is a script that takes GrapheneOS binary OTA updates and resigns them with your own signing keys (including support for automating the process and installing in Qubes), and also supports applying modifications, such as having ADB root and being able to backup all applications, that violate the Android security model that GrapheneOS wishes to uphold, not because they make the device less secure for you, but because they follow your own wishes over providing guarantees to app developers that the OS will behave in a certain way. It could also support resigning stock Android 12-13 OS images with very few modifications.

With resign-android-image, you can take back control of your Android device, by letting you run the OS (currently only GrapheneOS is supported) with a locked bootloader, but signed with your own keys instead of the upstream keys, and with some optional modifications including optional root access, without building it from scratch every time there is an update.

With this tool, you are no longer at the mercy of your OS' upstream developers, and can decide for yourself how you want to configure your device without having to wipe /data and reinstall on every change, all without compromising the security of your own device by not locking the bootloader.

This tool works by resigning Android OS images with your own verified boot and APK keys and optionally making a few modifications by patching, such as enabling ADB root and removing a few antifeatures included in Android upstream. This is accomplished by reconstructing the target_files.zip from the upstream OTA updates, making changes, resigning it and rebuilding the images from it like a normal release, and building OTA and/or factory images.

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

It reruns itself with sudo in a mount namespace of its own, in which the tmp directory of the work directory is mounted over /tmp and /var/tmp, so that the large temporary files of the build go into the work directory. Where that isn't possible, such as in a container, use --no-unshare to run it as it is, with TMPDIR set to that directory instead, which only the tools that take the temporary directory from TMPDIR follow.

Use --ota to generate an OTA, --factory-image to generate a factory image flashable payload, and --factory-zip to generate a factory image.

The upstream OTA and factory images are downloaded into the work directory and deleted once extracted, unless --keep is given; use --download-cache DIR to download them into DIR instead and keep them there, so that they are downloaded only once for any number of work directories.

Use --threads N to sign the APKs and APEXes, and extract the images, N at a time instead of as many at a time as there are CPUs.

The modifications that patch the code of jars and APKs, like the ones of framework.jar and services.jar, leave stale what the build compiled from them and against them ahead of time: the boot image, which the device can't start without, the system server jars and, once the framework is patched, every app. These are compiled again as the build compiled them, with the dex2oat of the same build on the Android CI that the otatools come from, from the profiles and the other files that the images have for the device to compile them with, and with the options that the files they replace were compiled with; compiling the smallest one of them and, if it is stale, the boot image again from the original files first must reproduce the ones in the images, but for the hash of the file, which the build computes over garbage left in it. In a gVisor sandbox configured with a platform that takes the GS register for itself, which makes dex2oat abort as it starts, dex2oat is run with qemu-user, which emulates the register but is about ten times slower. Use --no-dex2oat to remove the stale files instead, for the device to compile them itself as it boots and later.

You can use --generate-keys to automatically generate keys if the key directory doesn't exist.

You can use --version to give the resigned images a version (build number) different from the one of the upstream build they are made from: the build number in the build.prop files (including the one embedded in the fingerprints) is replaced with it, and the generated OTA and factory images are named after it.

The build timestamps (ro.\*.date.utc, plus the human readable ro.\*.date) are replaced with one synthesized from the version. This is necessary because the updater only offers an update whose timestamp in the release metadata is greater than ro.build.date.utc of the running build (the build number is only used to check that an incremental update applies to the running build), and update_engine and the recovery refuse to install a package older than the running build. It also means that you can install an older OS version over a newer one by giving it a version higher than the one currently running. For the same reason a version of a day after the current one (in UTC) is refused: a device running it would refuse every release up to that day, sideloaded ones included.

Upstream timestamps cannot be reused or recomputed, since they are the wall clock time of the release build run (which is why reproducing a GrapheneOS build requires exporting the BUILD_DATETIME of the original build) and a version that upstream never built has no such time. Instead, since build numbers are YYYYMMDDXX, the timestamp used is the one of the last 100 seconds of the day of the version, one second per unit of XX. Timestamps synthesized this way are ordered like the build numbers they come from, are always later than those of the real releases of the same day or an earlier one, which are built during their own day, and always earlier than those of the real releases of a later day, which can thus always still be installed.

The day is taken in UTC, which is the timezone build numbers are assigned in: the releases built at 03:27:33 UTC, 04:48:18 UTC and 06:01:10 UTC all have the build number of the UTC day they were built in, while in the local time of the GrapheneOS developers the first two would have belonged to the previous day. This is what makes being earlier than every later release hold exactly, rather than only for the times of the day at which releases happen to be built now.

The images are built by the standard Android image building code, which sign_target_files_apks runs at the end of signing just like for a normal release, out of target files whose inputs are reconstructed from the original images. Since the images of a release are built this way, anything the target files cannot express cannot be in them, and the build fails rather than drop it if it is.

The owner, group, mode, capabilities and SELinux label of every file of the filesystem images are read out of the original images, without mounting them, and written to the META/\*filesystem_config.txt and META/file_contexts.bin files that the build takes them from. The labels come from the file_contexts of the SELinux policy in the images, which is how a normal build labels files, so that files added by the modifications get the label the policy gives them; a file whose original label is not the one the policy gives it is pinned to its original label. The boot, init_boot and vendor_boot images are unpacked into the BOOT, INIT_BOOT and VENDOR_BOOT directories, the metadata of the files of their ramdisks goes into META/\*_filesystem_config.txt and META/ramdisk_node_list, and their headers and footers into misc_info.txt, while a boot image without a ramdisk (or the one given with --replace-boot), the dtbo image and the pvmfw image are used as prebuilt ones that the build adds a footer to, with the signing also replacing the key of the virt APEX that pvmfw embeds with the one it signs the APEX with; vbmeta is built while signing as well, and every partition it verifies must be one of these. Every built image is then checked against the original one: the files of a filesystem image must be exactly the expected ones, with exactly the expected metadata; a boot image must have the same header and files, and ramdisks holding files with the same names, metadata and contents, but for the contents of the otacerts.zip whose keys the signing replaces and of those that the options change (build.prop and prop.default for the options that change properties, the adbd of the recovery for --recovery-adb-root), since the recovery that the next OTA is sideloaded with is in them; a prebuilt image other than pvmfw must be unchanged, but for the version of avbtool recorded in its footer, while the one given with --replace-boot is checked with the same boot image verifier, allowing only explicitly permitted ramdisk changes; and vbmeta must verify the same partitions with the same rollback index, and every image must verify with it and the AVB key, as the bootloader verifies them. Only ext4 filesystem images and vbmeta images that don't chain to other ones are supported.

For debugging, use --keep to keep intermediate files and --keep-tmp to keep temporary files, --setx to show commands executed, --zip-opt 0 to speed up zipping during development, and --timing to show how long making each file took, including the files it needed, on the MADE lines.

Use --otatools-only to only set up the otatools that the build would use, which the otatools symlink in the work directory then points to, and stop there without building anything.

The files in the work directory are only made when missing, so the options that change what is made (the upstream build, the key directory, the version and every modification) are recorded in its options file, and the script refuses to run in it with other ones, since what was made with the old options would end up in the images; use another work directory, or remove what the changed options affect and pass --reuse-with-changed-options to have the new options recorded instead.

Read the rest of this document and the source code of the script to find out the other options.

# Tests

`tests/run` resigns the current stable release of raven (or the device and build given with --device and --build) once for each test, each time in a work directory of its own under ~/resign-android-image-tests (or the directory given with --work) with freshly generated keys, and checks the result with other tools than the ones the script uses to check it itself: that the OTA is signed with the generated key rather than the upstream one, that vbmeta is signed with the generated AVB key and verifies every image of the OTA, that the factory image and its signature use the generated keys, that the update server metadata is right, and that the modifications given in the options are in the images. The unit test instead only has the script set up the otatools of the release, and runs with them the unit tests in the tests directory, which check that the checks the script makes on the images it builds refuse images made to fail them. `tests/run --list` lists the tests and `tests/run TEST...` only runs the given ones; the options after `--` are passed on to every run of the script, such as --no-unshare in a container, or --timing. The upstream images are downloaded once into ~/.cache/resign-android-image (or the directory given with --download-cache) and kept there for the next runs. Each test takes as long as resigning a release, and needs about 32GB of disk space; the work directory of a test that fails is kept, with the output of the script in its log file.

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
8. Run the resigning script once manually in the signing VM with --generate-keys to generate keys and debug any issues
9. Enable and start the dom0 systemd timer that will automatically trigger updates, as instructed by the qubes-dom0-install script

If you don't want to use Qubes (note that having a secure workstation is crucial, which means not browsing the web or accessing untrusted data or running untrusted apps outside of dedicated VMs), read what qubes-dom0-install script does and mimic its behavior for your own setup.

# What could go wrong?

The situation to avoid is ending up in a state where there is no way to update the device via an OTA (you can't use fastboot with a locked bootloader), which can result in complete loss of data if the device also doesn't boot, complete loss of non-root-accessible data if root is disabled, and even an unrecoverable device if you disabled OEM unlocking.

Note that not locking the bootloader will make this situation impossible (you can always reflash from the bootloader), but at the cost of letting exploits be persistent, and evil maids replace your OS with impunity.

It would of course be ideal if Google had properly designed the Pixel devices and allowed fastboot flashing even with a locked bootloader (it's not clear why it's disabled since secure boot will just cause the device to fail to boot if you don't flash correctly signed data), but in practice it's probably quite unlikely that you will lock yourself out of the device like this.

On the other hand, if you can update the device with an OTA, you can just sign an update with ADB root enabled, or even root in the recovery and fix any issue using root privileges.

## Broken OTA updaters with no root

The main way that it could happen is if the OTA boots successfully (so the OS doesn't revert to the previous boot slot), but both the recovery and system updater don't work or have the wrong keys. To try to avoid this situation, this script will re-extract generated OTAs and factory images to make sure that the keys in otacerts.zip are correct, taking the one of the recovery from all the ramdisks it boots with (vendor_boot, boot and init_boot), which must hold a single one since they are unpacked over each other, and check that the recovery in the OTA accepts the signatures of the OTA and of its payload, as it has to for the next OTA to be sideloaded, and that it is of the device and has the build timestamp of the system, which the OTA must not be older than. Having root enabled can provide an extra way of applying updates in this case. You may also be able to open the device and reprogram the UFS flash if you really need to.

The OTA release certificate is checked against recovery's supported algorithms and RSA parameters before every build, and again as found in the recovery of every OTA and factory image built, whose otacerts.zip must hold it and nothing else: RSA-2048 or RSA-4096 with exponent 3 or 65537, and a certificate signature algorithm accepted by recovery. This prevents supplied keys that pass host signature verification but cannot be loaded by recovery. Automatically generated keys already meet these requirements.

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

ADB root also adds a SELinux policy extracted from a vanilla userdebug build to make the superuser permissive and also allow a bunch of other domains to interact with it (mostly to reply to requests made by the superuser). The precompiled policy of the vendor partition is then compiled again from the CIL files that init would compile it from at boot, with the otatools secilc, after checking that compiling them unmodified reproduces the original precompiled policy exactly, and its hash files are updated so that init keeps loading it rather than compiling the policy at every boot. This also removes the neverallow checks (they fail because the exclusions for su are compiled out, and fixing them is complicated); note that the neverallow checks do nothing at runtime and are merely a sanity check that already passes since otherwise the upstream OTA would have failed to build.

Note that no "su" binary is shipped.

Security impact: an exploit can potentially become persistent by enabling network ADB and whitelisting their own keys; exploits that somehow allow unauthorized ADB access will now give root to the attacker

## ADB at boot

A device that fails to complete the boot process cannot be debugged over ADB at all: ADB is off until it is enabled in the settings, the host has to be authorized in a dialog on a screen that a broken boot may never reach, and the GrapheneOS USB-C port setting disables the USB data lines while the device is locked, which it is for the whole of a boot.

By using --adb-key, you can bake an ADB public key into the image, so that the host holding the matching private key is authorized with no dialog on the device. The argument is a key file in the format of the ~/.android/adbkey.pub of an ADB host, and the option can be repeated to authorize several hosts. The keys are written to /adb_keys, which is one of the only two paths adbd reads keys from; the other one is in /data, which is wiped along with the user data and can only be written by a device that boots.

By using --adb-at-boot, you can have ADB turned on at every boot by an init script installed in /system/etc/init. The script sets sys.usb.config at early-init, before everything a broken boot can hang on, and then, once the persistent properties have been read from /data, sets persist.sys.usb.config to "adb", which is how a debuggable build turns ADB on: init mirrors that property into sys.usb.config at boot, and the system server decides from it that USB debugging is on when it takes the USB gadget over from init. This also writes that decision to the adb_enabled setting, so USB debugging shows as on in Settings, and turning it off there only lasts until the next boot.

The script also sets the GrapheneOS USB-C port setting (the persist.security.usb_mode property) to "charging-only when locked, except before first unlock", because its default of "charging-only when locked" cuts the USB data lines whenever the device is locked, which includes the whole of a boot that never reaches an unlock; note that this pins the setting, which is set again at every boot no matter what was chosen in Settings.

By using --adb-until-unlock instead, ADB is only turned on until the device is first unlocked, and without changing any setting. Only the non-persistent sys.usb.config property is set, at early-init and again at boot, since loading the persistent properties from /data turns it back off in between, so that nothing is written to /data: the framework decides at boot whether USB debugging is on by looking at persist.sys.usb.config, and then writes that decision to the adb_enabled setting, so setting the persistent property would permanently turn on USB debugging. Instead, the body of AdbService.systemReady() in services.jar is replaced with an assignment of the field that holds that decision, which makes the system server come up with USB ADB enabled while reading neither the property nor writing the setting; without it the system server would take the ADB function away from the USB gadget as soon as it takes the gadget over from init, which happens long before the device can be unlocked. Two side effects are worth knowing about: wireless debugging, which the original body restores from a property of its own, has to be enabled again in the settings after every boot, and the USB debugging switch in the settings shows ADB as off while it is on, so turning it on and then off again is what turns it off for the rest of the boot.

Once the device is unlocked for the first time, the boot has evidently worked, and with --adb-until-unlock the init script stops adbd again. This is a best effort: the system server still believes USB debugging is on for the rest of the boot, so anything that makes it reconfigure the USB gadget, such as unplugging and replugging the cable, starts adbd again.

By using --adb-at-boot-any-key-INSECURE, you get everything --adb-at-boot does and, in addition, adbd accepts any host key with no on-screen authorization, so you do not need to bake a key in with --adb-key. It works by clearing ro.adb.secure in build.prop, which is what makes adbd demand an authorized key; an eng build ships it cleared for the same effect. As the INSECURE in the name warns, this means anyone who can reach the USB (or, once it is enabled, network) ADB interface can connect with a key of their own, so it is only for a device you keep under physical control.

Security impact: anyone holding the private key of a baked in ADB public key can get a shell, a root one with --adb-root, on a device that hasn't been unlocked since it booted, and with --adb-at-boot also on an unlocked one; with --adb-at-boot-any-key-INSECURE no baked in key is needed and any host key is accepted, so anyone who can reach the ADB interface can get that shell; the USB attack surface of the device is also exposed while it hasn't been unlocked since it booted, rather than being disabled along with the data lines

## Ignore allowbackup and `<full-backup-content><exclude>`

The Android upstream OS contains antifeatures called "allowbackup=false" and "`<full-backup-content><exclude>`" that let application developers arbitrarily decide that the OS should not allow you to backup your own files that happen to be in the directory designated as their application's data directory.

By using --allowbackup, you can remedy the situation by making sure that the OS always ignores those decisions made against your interests. It works by making the already existing feature that only applies to apps targeting SDK >= 31 to all apps regardless of app version by patching the compat changes XML.

Unfortunately, the app is still allowed to exclude specific files from backup with `<data-extraction-rules><device-transfer><exclude>`, although hopefully that functionality will not be used. Currently there is no remedy for this, but root access can be used to access and modify the files freely, as it should be.

Security impact: attackers who gain access to the backup system will be able to extract more data, including data that app developers consider to be especially sensitive

## ADB backup

Recent Android upstream OS versions contain an antifeature that seeks to limit your access to your own data by disabling ADB backup for your own files that happen to be in directories designated as the data directory of an application targeting SDK >= 31.

By using --adb-backup, you can remedy the situation and disable this antifeature. It works by making it only apply to SDK >= 99 (which hopefully won't happen anytime soon) by patching the compat changes XML

Security impact: attackers who gain access to ADB will be able to extract more data, including data that app developers consider to be especially sensitive

## Localhost servers across user profiles

Android 17 restricts applications from connecting to localhost servers that are listening in a different Android user profile. This is a backwards-compatibility breaking change: setups that rely on running a server in one profile and using it from another one, which worked on all previous Android versions, stop working after updating.

By using --cross-profile-localhost, you can restore the pre-Android 17 behavior of allowing connections to localhost regardless of the profile the listening process happens to be running in.

It works by overwriting the bytecode of BpfNetMaps$Dependencies.isLoopbackChecksEnabled() in service-connectivity.jar (in the tethering APEX, mounted at /apex/com.android.tethering/javalib/) so that it returns false, which makes the connectivity service never install the eBPF loopback restrictions, and then repacking the APEX. The dex file is patched where it is inside the jar, so the only bytes of the jar that change are those of that one method, and the repacked APEX is checked to hold the same payload as the original one, with the same file names, permissions, contents and SELinux labels.

Security impact: applications can connect to localhost servers of other profiles, as they could before Android 17; this weakens the isolation between profiles for applications that listen on localhost without authenticating their clients

## AdAway or custom hosts file

Android developers often release applications infested with advertisements for their own personal gain at your expense.

You can remedy this situation by enabling Private DNS and setting it to dns.adguard.com. If you don't like sending all you DNS requests to AdGuard, you can use --hosts-url URL or --adaway (which is --hosts-url https://adaway.org/hosts.txt) to replace the hosts file with one that can block a lot of advertising and tracking related domains.

Security impact: none affecting you

Functionality impact: you will not be able to access the blocked domains even if want to

## Magisk (manual)

You can install Magisk even though it's not recommended since it's not clear whether the Magisk author properly designed it in a secure way.

Pass a replacement boot.img with `--replace-boot IMAGE`. By default, the existing boot image verifier requires its header, kernel and ramdisk files to match the original build, including file contents, metadata and order.

Use `--replace-boot-allow-change "init path/to/file"` to allow content changes to the listed existing ramdisk files and additions at those exact paths. Paths are literal, relative to the ramdisk root, separated by spaces; the option can be repeated. Existing files must retain their metadata and cannot be removed. Use `--replace-boot-allow-new-files` to permit any new ramdisk paths (including directories), while still checking every existing file. Parent directories added for a listed file must also be allowed. These options do not permit changes to the kernel or boot header.

A Magisk-patched image therefore needs explicit allowances for its changes and must still satisfy the remaining checks. Permitting a change to a boot-critical file does not establish that the modified file will work in recovery.

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
