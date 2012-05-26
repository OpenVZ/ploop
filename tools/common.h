#ifndef __COMMON_H_
#define __COMMON_H_

int parse_size(const char * opt, off_t * sz);
int parse_format_opt(const char *opt);
int is_xml_fname(const char *fname);

#endif // __COMMON_H_
