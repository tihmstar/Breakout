#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <plist/plist.h>

#include <string.h>

#define DBUG(v) printf("%s:%p\n", #v, v);

char *plist_stringFromType(plist_type t) {
	char *r = NULL;
	switch (t) {
	case PLIST_BOOLEAN:
		r = "BOOL";
		break;
	case PLIST_UINT:
		r = "unsigned";
		break;
	case PLIST_REAL:
		r = "real";
		break;
	case PLIST_STRING:
		r = "string";
		break;
	case PLIST_ARRAY:
		r = "array";
		break;
	case PLIST_DICT:
		r = "dictionary";
		break;
	case PLIST_DATE:
		r = "date";
		break;
	case PLIST_DATA:
		r = "data";
		break;
	case PLIST_KEY:
		r = "key";
		break;
	case PLIST_NONE:
		r = "none";
		break;
	}
	return r;
}

char plist_from_file(const char *path, plist_t *p) {
printf("\n%s {\n", __PRETTY_FUNCTION__);

	struct stat sb;
	if (stat(path, &sb) == -1) {
		return 1;
	}
	uint32_t size = sb.st_size;
printf("size: %d\n", size);

	//read input file
	FILE *fp = fopen(path, "rb");
	if (!fp) {
		return 2;
	}
	char *buffer = (char *) malloc(size * sizeof(char));
	int read_size = fread(buffer, sizeof(char), size, fp);
	fclose(fp);

    plist_t root_node = NULL;
	if (memcmp(buffer, "bplist00", 8) == 0) {
printf("binary\n");
	plist_from_bin(buffer, read_size, &root_node);
	} else {
printf("xml\n");
	plist_from_xml(buffer, read_size, &root_node);
	}
DBUG(root_node);
free(buffer);
	*p = root_node;

printf("}\n");
	return 0;
}

char plist_to_file(const char *path, plist_t *root_node, const char c) {
printf("\n%s {\n", __PRETTY_FUNCTION__);
    
    
DBUG(root_node);
	char *buffer;
	uint32_t size = 0;
	switch (c) {
	case 'x':
	plist_to_xml(root_node, &buffer, &size);
		break;
	case 'b':
	plist_to_bin(root_node, &buffer, &size);
		break;
	default:
		return 1;
	}
DBUG(buffer);
printf("size: %d\n", size);
	if (size == 0) {
		return 2;
	}
	FILE *fp = fopen(path, "wb");
	if (!fp) {
		return 3;
	}
fwrite(buffer, size, sizeof(char), fp);
	fclose(fp);
//SC;	free(buffer);

printf("}\n");
	return 0;
}


void doStuff(const char *path, const char *pathOut) {
printf("\n%s {\n", __PRETTY_FUNCTION__);

	char c;
	plist_t root_node = NULL;
c = plist_from_file(path, &root_node);
printf("\nwrite4file:%s\n", c?"NO":"OK");
DBUG(root_node);
    
plist_t dict1 = plist_new_dict();
DBUG(dict1);
    plist_t userPos = NULL;
    userPos = plist_dict_get_item(root_node, "User");
    
    plist_t wwdcPos = NULL;
    wwdcPos = plist_dict_get_item(userPos, "developer.apple.wwdc-Release");
    
    plist_t envPos = NULL;
    envPos = plist_dict_get_item(wwdcPos, "EnvironmentVariables");
    
    
plist_t string = plist_new_string("/private/var/mobile/Media/Downloads/WWDC.app/gameover.dylib");
DBUG(string);
plist_dict_insert_item(envPos, "DYLD_INSERT_LIBRARIES", string);
plist_dict_remove_item(envPos, "CFFIXED_USER_HOME");
plist_dict_remove_item(envPos, "HOME");
plist_dict_remove_item(envPos, "TMPDIR");
    
    char *unused = NULL;
    free(unused);
    
c = plist_to_file(pathOut, root_node, 'b');
printf("\nwrite2file:%s\n", c?"NO":"OK");

	//not sure what to freed and what not
	//plist_free(root_node);
printf("}\n");
}




/*

int main(int argc, char **argv, char **envp) {
	if (argc != 3) {
		return 1;
	}
	//char *path = "./com.apple.mobile.installation.plist";
	doStuff(argv[1], argv[2]);
	return 0;
}
 */
