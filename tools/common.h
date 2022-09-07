#ifndef __COMMON_H_
#define __COMMON_H_

int parse_size(const char *opt, off_t *sz, const char *name);
int parse_format_opt(const char *opt);
char *parse_uuid(const char *opt);
int is_xml_fname(const char *fname);
void init_signals(void);

#define USAGE_FORMATS	"{ raw | ploop1 | expanded | preallocated }"
#define USAGE_VERSIONS	"{ 1 | 2 } (default 2, if supported)"

#endif // __COMMON_H_
