#ifndef __COMMON_H_
#define __COMMON_H_

int parse_size(const char * opt, off_t * sz);
int parse_format_opt(const char *opt);
int is_xml_fname(const char *fname);
int read_dd(struct ploop_disk_images_data **di, const char *file);

#endif // __COMMON_H_
