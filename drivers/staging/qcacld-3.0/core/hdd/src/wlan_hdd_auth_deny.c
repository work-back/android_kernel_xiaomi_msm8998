#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/spinlock_types.h>
#include <linux/if_ether.h>

#include "wlan_hdd_auth_deny.h"


static spinlock_t ad_lock;
static struct list_head ad_deny_list;

typedef struct ad_sta {
	struct list_head list;
	u8 	mac[ETH_ALEN];
}ad_sta_t;

static int ad_compare_ether_addr(const u8 *addr1, const u8 *addr2)
{
	const u16 *a = (const u16 *) addr1;
	const u16 *b = (const u16 *) addr2;

	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) != 0;
}

void auth_deny_sta_add(const u8* mac)
{
    ad_sta_t *p = NULL, *n = NULL;
    spin_lock(&ad_lock);

    list_for_each_entry(p, &ad_deny_list, list) {
       if (!ad_compare_ether_addr(mac, p->mac)) {
           goto _exit_sta_add;
       }
    }

    n = kmalloc(sizeof(ad_sta_t), GFP_ATOMIC);
    if (!n) {
        goto _exit_sta_add;
    }
    memcpy(n->mac, mac, ETH_ALEN);

    list_add_tail(&(n->list), &ad_deny_list);

_exit_sta_add:
    spin_unlock(&ad_lock);

    return;
}

void auth_deny_sta_del(const u8* mac)
{
    ad_sta_t *p = NULL, *n = NULL;
    spin_lock(&ad_lock);

    list_for_each_entry_safe(p, n, &ad_deny_list, list) {
       if (!ad_compare_ether_addr(mac, p->mac)) {
           list_del_init(&(p->list));
           kfree(p);
       }
    }

    spin_unlock(&ad_lock);

    return;
}

int auth_deny_sta_check(const u8* mac)
{
    int ret = 0;
    ad_sta_t *p = NULL;
    spin_lock(&ad_lock);

    list_for_each_entry(p, &ad_deny_list, list) {
       if (!ad_compare_ether_addr(mac, p->mac)) {
           ret = 1;
       }
    }

    spin_unlock(&ad_lock);

    return ret;
}

int auth_deny_sta_dump2buf(char *buf, int buf_len)
{
    int ret = 0;
    ad_sta_t *p = NULL;
    spin_lock(&ad_lock);

    list_for_each_entry(p, &ad_deny_list, list) {
        ret += snprintf(buf + ret, buf_len - ret, MAC_FMT"\n", MAC2STR(p->mac));
    }

    spin_unlock(&ad_lock);

    return ret;
}

void wlan_hdd_auth_deny_init(void)
{
    spin_lock_init(&ad_lock);
    INIT_LIST_HEAD(&ad_deny_list);

    return;
}

void wlan_hdd_auth_deny_deinit(void)
{
    ad_sta_t *p = NULL, *n = NULL;
    spin_lock(&ad_lock);

    list_for_each_entry_safe(p, n, &ad_deny_list, list) {
        list_del_init(&(p->list));
        kfree(p);
    }

    spin_unlock(&ad_lock);

    return;
}

