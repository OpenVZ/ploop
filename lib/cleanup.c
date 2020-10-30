/*
 *  Copyright (c) 2008-2017 Parallels International GmbH.
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>

#include "list.h"
#include "cleanup.h"
#include "ploop.h"
struct ploop_cancel_handle
{
	list_head_t head;
	int flags;
};

struct ploop_cleanup_hook {
	list_elem_t list;
	cleanup_FN fn;
	void *data;
};

static __thread struct ploop_cancel_handle __cancel_data;

/* set cancel flag
 *  * Note: this function also clear the flag
 *   */
int is_operation_cancelled(void)
{
	struct ploop_cancel_handle *cancel_data;

	cancel_data = ploop_get_cancel_handle();
	if (cancel_data->flags) {
		cancel_data->flags = 0;
		return 1;
	}
	return 0;
}

struct ploop_cancel_handle *ploop_get_cancel_handle(void)
{
	return &__cancel_data;
}

struct ploop_cleanup_hook *register_cleanup_hook(cleanup_FN fn, void *data)
{
	struct ploop_cleanup_hook *h;
	struct ploop_cancel_handle *handle = ploop_get_cancel_handle();
	list_head_t *head = &handle->head;

	if (head->next == NULL)
		list_head_init(head);

	h = malloc(sizeof(struct ploop_cleanup_hook));
	if (h == NULL)
		return NULL;
	h->fn = fn;
	h->data = data;
	list_add(&h->list, head);

	return h;
}

void unregister_cleanup_hook(struct ploop_cleanup_hook *h)
{
	if (h != NULL) {
		list_del(&h->list);
		free(h);
	}
}

void ploop_cancel_operation(void)
{
	struct ploop_cleanup_hook *it;
	struct ploop_cancel_handle *handle = ploop_get_cancel_handle();
	list_head_t *head = &handle->head;

	handle->flags = 1;

	if (head->next != NULL) {
		list_for_each(it, head, list) {
			it->fn(it->data);
		}
	}
}
