#ifndef __COMMON_H_
#define __COMMON_H_

int parse_size(const char *opt, off_t *sz, const char *name);
int parse_format_opt(const char *opt);
char *parse_uuid(const char *opt);
int is_xml_fname(const char *fname);
#define read_dd ploop_read_disk_descr
void init_signals(void);

#endif // __COMMON_H_
