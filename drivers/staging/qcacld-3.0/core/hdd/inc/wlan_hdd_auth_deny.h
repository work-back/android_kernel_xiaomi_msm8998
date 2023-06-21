#ifndef _WLAN_HDD_AUTH_DENY_H
#define _WLAN_HDD_AUTH_DENY_H

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(m) (m)[0],(m)[1],(m)[2],(m)[3],(m)[4],(m)[5]

void auth_deny_sta_add(const u8* mac);
void auth_deny_sta_del(const u8* mac);
int auth_deny_sta_check(const u8* mac);
int auth_deny_sta_dump2buf(char *buf, int buf_len);
void wlan_hdd_auth_deny_init(void);
void wlan_hdd_auth_deny_deinit(void);

#endif //_WLAN_HDD_AUTH_DENY_H
