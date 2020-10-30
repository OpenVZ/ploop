#ifndef __CLEANUP_H__
#define __CLEANUP_H__

struct ploop_cleanup_hook;
struct ploop_cancel_handle;

typedef void (* cleanup_FN) (void *data);

#ifdef __cplusplus
extern "C" {
#endif
int is_operation_cancelled(void);
struct ploop_cancel_handle *ploop_get_cancel_handle(void);
struct ploop_cleanup_hook *register_cleanup_hook(cleanup_FN f, void *data);
void unregister_cleanup_hook(struct ploop_cleanup_hook *h);
#ifdef __cplusplus
}
#endif
#endif
