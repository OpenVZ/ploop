#include "libploop.h"
#include "ploop.h"

#define DEPR_ERROR \
	ploop_err(0, "%s is deprecated, DO NOT USE!", __func__)

char *ploop_get_base_delta_uuid(struct ploop_disk_images_data *di) {
	DEPR_ERROR;

	return NULL;
}
