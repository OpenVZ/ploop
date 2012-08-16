#ifndef __CLEANUP_H__
#define __CLEANUP_H__

#include "list.h"

struct ploop_cancel_handle
{
	list_head_t head;
	int flags;
};

typedef void (* cleanup_FN) (void *data);

struct ploop_cleanup_hook {
	list_elem_t list;
	cleanup_FN fn;
	void *data;
};

#ifdef __cplusplus
extern "C" {
#endif
struct ploop_cancel_handle *ploop_get_cancel_handle(void);
struct ploop_cleanup_hook *register_cleanup_hook(cleanup_FN f, void *data);
void unregister_cleanup_hook(struct ploop_cleanup_hook *h);
#ifdef __cplusplus
}
#endif
#endif
