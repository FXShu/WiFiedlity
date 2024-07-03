#include "crypto/crypto.h"
#include "utils/common.h"
#include "utils/print.h"
#include <stdint.h>
int debug_level;

void usage(){
	printf("data_decryption usage:\n"
		"data_decryption -k <ptk> [-d<debug level>]...\n"
		"  -k = complete ptk\n");
}

static int parse_tk_from_string(struct wpa_ptk *ptk, char *key_str, int len) {
	if (!ptk || !key_str || len <= 0) {
		log_printf(MSG_ERROR, "%s: invalid input", __func__);
		return -1;
	}
	int index = 0;
	for (char *tmp = strtok(key_str, "-"); tmp; tmp = strtok(NULL, "-")) {
		if (index >= 8) {
			log_printf(MSG_ERROR, "%s: length of key is too long", __func__);
		}
		if (strlen(tmp) != 4) {
			log_printf(MSG_ERROR, "%s: invalid key format %s", __func__, tmp);
			return -1;
		}
		long int key_hex = strtol(tmp, NULL, 16);
		MITM_PUT_BE16(&ptk->tk1[index * 2], (uint16_t)key_hex);
		index++;
	}
	lamont_hdump(MSG_DEBUG, "Pair Transiant Key", ptk->tk1, sizeof(ptk->tk1));
	return 0;
}

static int parse_payload_from_string(uint8_t *buffer, int *buffer_len, char *payload_str, int len) {
	if (*buffer_len < (len / 2)) {
		log_printf(MSG_ERROR, "%s: payload length %d is too long", __func__, len);
		return -1;
	}
	int index = 0;
	char u8_str[2];
	while(len >= 2) {
		strncpy(u8_str, &payload_str[index * 2], 2);
		buffer[index] = (uint8_t)strtol(u8_str, NULL, 16);
		index++;
		len -= 2;
	}
	*buffer_len = index;
	log_printf(MSG_DEBUG, "Payload length = %d", *buffer_len);
	lamont_hdump(MSG_DEBUG, "Payload", buffer, index);
}

int main(int argc, char **argv){
	char payload_str[1024];
	char header_str[128];
	char key_str[64];

	struct wpa_ptk ptk;
	uint8_t buffer[1024];
	int buffer_len;
	uint8_t header[128];
	int header_len;

	uint8_t *plain;
	size_t plain_len;
	int c;

	buffer_len = 1024;
	header_len = 128;
	for(;;){
		c=getopt(argc, argv,"k:p:h:");
		if(c < 0)break;
		switch(c){
		case 'k':
			strncpy(key_str, optarg, 64);
		break;
		case 'p':
			strncpy(payload_str, optarg, 1024);
		break;
		case 'h':
			strncpy(header_str, optarg, 128);
		break;
		case 'd':
			debug_level = atoi(optarg);
		break;
		default:
	       		usage();
			return 0;
		}
	}

	parse_tk_from_string(&ptk, key_str, strlen(key_str));
	parse_payload_from_string(buffer, &buffer_len, payload_str, strlen(payload_str));
	parse_payload_from_string(header, &header_len, header_str, strlen(header_str));

	plain = ccmp_decrypt(ptk.tk1, (struct ieee80211_hdr_3addr *)header,
			buffer, buffer_len, &plain_len);
	lamont_hdump(MSG_DEBUG, "Plain", plain, plain_len);

	if (plain)
		free(plain);
	return 0;
exit:
	return -1;
}
