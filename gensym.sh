#!/bin/sh

SELF=$(basename $0)
usage() {
	echo "Usage: $SELF infile outfile" 1>&2
	echo "       $SELF libploop.h dynload.h" 1>&2
	echo "       $SELF libploop.h symbols.c" 1>&2
	exit 1
}

INPUT=$1
test -f $INPUT || usage
shift

# Extract only function prototypes from libploop.h
# 1 Only leave part inside extern "C" { .... }
# 2 Remove 'extern "C"' and the #ifdef/#endif
# 3 Remove empty lines and lines with /* comments
# 4 Remove extra spaces and tabs
# 5 Remove newlines, only add newlines after ;
extract_functions() {
	cat $INPUT | \
	  sed -n -e '/^extern "C" {$/,/^}$/p' | \
	  sed -n -e '3,$p' | head -n-2 | \
	  grep -v '^$' | grep -v '^\/\*' | \
	  sed 's/[ \t][ \t]*/ /g' | \
	  tr -d '\n' | sed 's/;/;\n/g'
}

disclaimer() {
	echo "/* This file is auto-generated from $INPUT by $SELF."
	echo " * DO NOT EDIT"
	echo " */"
}

gen_h() {
	# Make list of pointers to functions
	extract_functions | sort | \
	  sed 's/\(^.*[* ]\)ploop_\([a-z_]*\)\((.*\)$/\t\1(*\2)\3/'
}

gen_c() {
	disclaimer
	echo
	echo "#include <libploop.h>"
	echo "#include <dynload.h>"
	echo
	echo "void ploop_resolve_functions(struct ploop_functions * f) {"
	echo "#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))"
	echo "BUILD_BUG_ON(sizeof(*f) != 64*sizeof(void *));"
	# Initialize the structure with names
	extract_functions | \
	  sed 's/^.*[* ]ploop_\([a-z_]*\)(.*$/\1/' | \
	  awk '{printf "\tf->%-30s\t= ploop_%s;\n", $1, $1; }'

	echo "};"
}

case $1 in
	*.h)
		gen_h > $1
		;;
	*.c)
		gen_c > $1
		;;
	*)
		usage
		;;
esac
