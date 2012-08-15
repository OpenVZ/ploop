#!/bin/sh

SELF=$(basename $0)
usage() {
	echo "Usage: $SELF infile outfile" 1>&2
	echo "       $SELF libploop.h libploop-sym.h" 1>&2
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
	disclaimer
	echo
	echo "#include <sys/types.h>"
	echo "#include <linux/types.h>"
	echo
	echo "struct ploop_functions {"
	# Make list of pointers to functions
	extract_functions | \
	  sed 's/\(^.*[* ]\)ploop_\([a-z_]*\)\((.*\)$/\t\1(*\2)\3/'

	echo "};"
	echo
	echo '__attribute__ ((visibility("default")))'
	echo "void ploop_resolve_functions(struct ploop_functions * f);"
}

gen_c() {
	disclaimer
	echo
	echo "#include <libploop.h>"
	echo "#include <libploop-sym.h>"
	echo
	echo "void ploop_resolve_functions(struct ploop_functions * f) {"
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
