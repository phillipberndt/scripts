# bpath: Add local prefix to influential environment variables
#
# Copyright (c) Phillip Berndt, 2016-2017.

_bpath_add_path() {
	local NAMES VALUE NAME NAMES_ARRAY

	NAMES=$1
	VALUE=$(readlink -f "$2" 2>/dev/null)

	if [ ! -d "$VALUE" ]; then
		return
	fi

	NAMES_ARRAY=("${(@s/:/)NAMES}")
	for NAME in $NAMES_ARRAY; do
		eval export $NAME

		if [ -n "${(P)NAME}" ]; then
			# This one is tricky: Expand $$NAME into an array, using : as a
			# separator, then check if $VALUE is literarilly contained as one
			# of the entries. If it is, return the last index, and 0 otherwise.
			if [ ${${(@s/:/)${(P)NAME}}[(I)${(q)VALUE}]} -gt 0 ]; then
				continue
			fi
			eval ${NAME}=\$VALUE:\$$NAME
		else
			eval ${NAME}=\$VALUE
		fi

		if [ "$VERBOSE" -eq 1 ]; then
			echo -e "\033[1m$NAME\033[0m += ( \033[32m$VALUE\033[0m )"
		fi
	done
}

_bpath_auto_add_path_recursive() {
	local NAME BASE ENAME P NAMES_ARRAY

	NAME=$1
	BASE=$2
	shift 2

	NAMES_ARRAY=("${(@s/:/)NAME}")
	for ENAME in $NAMES_ARRAY; do
		eval export $ENAME
	done

	while read P; do
		_bpath_add_path $NAME $P
	done < <(find $BASE $@ -printf "%h\n" | sort | uniq)
}

_bpath_help() {
	echo "Syntax: bpath [-hvc] [-d #] [-e NAME] <base directory> [\`find' arguments]"
	echo "Add local prefix to influential environment variables"
	echo
	if [ "$#" -lt 1 -o "$1" != "long" ]; then
		return
	fi
	echo "Options:"
	echo "  -h               Display this help"
	echo "  -v               Be verbose"
	echo "  -c               Create a standard /usr layout directory structure and add"
	echo "                   it to the environment. Requires an empty base directory"
	echo "  -d #             How deep to search for interesting directories,"
	echo "                   defaults to 3"
	echo "  -e NAME          Set only one specific environment variable"
	echo "                   (Or multiple, if separated by colons)"
	echo
	echo "Arguments:"
	echo "  base directory   Base directory to start the search from"
	echo "  find arguments   Optional arguments to pass to \'find'. All directories"
	echo "                   with results in them will be added to the environment"
	echo "                   variable."
	echo
	echo "By default, bpath tries to perform some magic to autodetermine what to"
	echo "add where. If directories lib, include, share, etc. are present, a local"
	echo "/usr like structure is assumed. Elsewise, bpath will search for *.so files"
	echo "and add them to LD_LIBRARY_PATH, executables are added to PATH, etc."
	echo
}

bpath() {
	local VARIABLES SEARCH_DEPTH VERBOSE ACTION OPTION VALUE ENAME ARCH

	VARIABLES_OVERRIDDEN=0
	VARIABLES=PATH:CPATH:LD_LIBRARY_PATH:LIBRARY_PATH:PKG_CONFIG_PATH:XDG_DATA_DIRS:DYLD_LIBRARY_PATH
	SEARCH_DEPTH=3
	VERBOSE=0
	ACTION=env

	while getopts "hve:cd:" OPTION; do
		case $OPTION in
			h)
				_bpath_help long
				return 0
				;;
			c)
				ACTION=create
				;;
			d)
				SEARCH_DEPTH=$((0 + $OPTARG))
				;;
			e)
				VARIABLES=$OPTARG
				VARIABLES_OVERRIDDEN=1
				;;
			v)
				VERBOSE=1
				;;
			*)
				_bpath_help >&2
				return 1
				;;
		esac
	done
	shift $OPTIND-1

	if [ "$#" -eq 0 ]; then
		_bpath_help
		return 1
	fi

	BASE_DIRECTORY=$1
	shift

	VARIABLES_ARRAY=("${(@s/:/)VARIABLES}")
	for ENAME in $VARIABLES_ARRAY; do
		eval export $ENAME
	done

	if [ "$ACTION" = "create" ]; then
		if [ "$#" -gt 0 ]; then
			_bpath_help >&2
			echo "Error: -c does not accept \`find' parameters." >&2
			return 1
		fi
		[ -d $BASE_DIRECTORY ] || mkdir $BASE_DIRECTORY || return 1
		if [ "$(ls $BASE_DIRECTORY)" != "" ]; then
			_bpath_help >&2
			echo "Error: $BASE_DIRECTORY is not empty." >&2
			return 1
		fi

		ARCH=$(arch)

		if [ ${VARIABLES_ARRAY[(i)PATH]} -le ${#VARIABLES_ARRAY} ]; then
			mkdir $BASE_DIRECTORY/bin
			_bpath_add_path PATH $BASE_DIRECTORY/bin
		fi
		if [ ${VARIABLES_ARRAY[(i)CPATH]} -le ${#VARIABLES_ARRAY} ]; then
			mkdir $BASE_DIRECTORY/include
			_bpath_add_path CPATH $BASE_DIRECTORY/include
		fi
		if [ ${VARIABLES_ARRAY[(i)LIBRARY_PATH]} -le ${#VARIABLES_ARRAY} ]; then
			mkdir -p $BASE_DIRECTORY/lib/$ARCH-linux-gnu
			_bpath_add_path LIBRARY_PATH $BASE_DIRECTORY/lib/$ARCH-linux-gnu
			_bpath_add_path LIBRARY_PATH $BASE_DIRECTORY/lib
		fi
		if [ ${VARIABLES_ARRAY[(i)LD_LIBRARY_PATH]} -le ${#VARIABLES_ARRAY} ]; then
			mkdir -p $BASE_DIRECTORY/lib/$ARCH-linux-gnu
			_bpath_add_path LD_LIBRARY_PATH $BASE_DIRECTORY/lib/$ARCH-linux-gnu
			_bpath_add_path LD_LIBRARY_PATH $BASE_DIRECTORY/lib
		fi
		if [ ${VARIABLES_ARRAY[(i)PKG_CONFIG_PATH]} -le ${#VARIABLES_ARRAY} ]; then
			mkdir -p $BASE_DIRECTORY/lib/pkgconfig
			_bpath_add_path PKG_CONFIG_PATH $BASE_DIRECTORY/lib/pkgconfig
			mkdir -p $BASE_DIRECTORY/lib/$ARCH-linux-gnu/pkgconfig
			_bpath_add_path PKG_CONFIG_PATH $BASE_DIRECTORY/lib/$ARCH-linux-gnu/pkgconfig
		fi
		if [ ${VARIABLES_ARRAY[(i)XDG_DATA_DIRS]} -le ${#VARIABLES_ARRAY} ]; then
			mkdir $BASE_DIRECTORY/share
			_bpath_add_path XDG_DATA_DIRS $BASE_DIRECTORY/share
		fi
		return 0
	fi

	if [ "$#" -gt 0 ]; then
		_bpath_auto_add_path_recursive $VARIABLES $BASE_DIRECTORY -maxdepth $SEARCH_DEPTH $@
	elif [ -d $BASE_DIRECTORY/bin -o -d $BASE_DIRECTORY/lib -o -d $BASE_DIRECTORY/include -o -d $BASE_DIRECTORY/share ]; then
		if [ "$VERBOSE" -eq 1 ]; then
			echo -e "\033[34mRunning in /usr-structure mode.\033[0m"
		fi
		if [ ${VARIABLES_ARRAY[(i)PATH]} -le ${#VARIABLES_ARRAY} ]; then
			_bpath_add_path PATH $BASE_DIRECTORY/bin
		fi
		if [ ${VARIABLES_ARRAY[(i)CPATH]} -le ${#VARIABLES_ARRAY} ]; then
			_bpath_add_path CPATH $BASE_DIRECTORY/include
			_bpath_auto_add_path_recursive CPATH $BASE_DIRECTORY/include -mindepth 1 -maxdepth $SEARCH_DEPTH "(" -name "*.h" -o -type d ")"
		fi
		if [ ${VARIABLES_ARRAY[(i)LIBRARY_PATH]} -le ${#VARIABLES_ARRAY} ]; then
			_bpath_auto_add_path_recursive LIBRARY_PATH $BASE_DIRECTORY/lib -maxdepth $SEARCH_DEPTH "(" -regex ".+\\.so\\(\\.[0-9\\.-]+\\)?" -o -name "*.a" -o -name "*.la" ")"
		fi
		if [ ${VARIABLES_ARRAY[(i)LD_LIBRARY_PATH]} -le ${#VARIABLES_ARRAY} ]; then
			_bpath_auto_add_path_recursive LD_LIBRARY_PATH $BASE_DIRECTORY/lib -maxdepth $SEARCH_DEPTH -regex ".+\\.so\\(\\.[0-9\\.-]+\\)?"
		fi
		if [ ${VARIABLES_ARRAY[(i)PKG_CONFIG_PATH]} -le ${#VARIABLES_ARRAY} ]; then
			_bpath_add_path PKG_CONFIG_PATH $BASE_DIRECTORY/lib/pkgconfig
		fi
		if [ ${VARIABLES_ARRAY[(i)XDG_DATA_DIRS]} -le ${#VARIABLES_ARRAY} ]; then
			_bpath_add_path XDG_DATA_DIRS $BASE_DIRECTORY/share
		fi

		for ENAME in $VARIABLES_ARRAY; do
			KNOWN_VARIABLES=(PATH CPATH LIBRARY_PATH LD_LIBRARY_PATH PKG_CONFIG_PATH XDG_DATA_DIRS)
			if [ ${KNOWN_VARIABLES[(i)${(q)ENAME}]} -gt ${#KNOWN_VARIABLES} ]; then
				echo "Don't know how to handle $ENAME in a /usr-like directory structure." >&2
				echo "Please specify \`find' parameters explicitly." >&2
			fi
		done
	else
		if [ ${VARIABLES_ARRAY[(i)PATH]} -le ${#VARIABLES_ARRAY} ]; then
			_bpath_auto_add_path_recursive PATH $BASE_DIRECTORY -maxdepth $SEARCH_DEPTH -executable -type f
		fi
		if [ ${VARIABLES_ARRAY[(i)CPATH]} -le ${#VARIABLES_ARRAY} ]; then
			_bpath_auto_add_path_recursive CPATH $BASE_DIRECTORY -maxdepth $SEARCH_DEPTH -mindepth 1 "(" -name "*.h" -o -type d ")"
			_bpath_auto_add_path_recursive CPATH $BASE_DIRECTORY -maxdepth 1 -name "*.h"
		fi
		if [ ${VARIABLES_ARRAY[(i)LIBRARY_PATH]} -le ${#VARIABLES_ARRAY} ]; then
			_bpath_auto_add_path_recursive LIBRARY_PATH $BASE_DIRECTORY -maxdepth $SEARCH_DEPTH "(" -name "*.so" -o -name "*.a" -o -name "*.la" -o -name "*.dylib" ")"
		fi
		if [ ${VARIABLES_ARRAY[(i)LD_LIBRARY_PATH]} -le ${#VARIABLES_ARRAY} ]; then
			_bpath_auto_add_path_recursive LD_LIBRARY_PATH $BASE_DIRECTORY -maxdepth $SEARCH_DEPTH -name "*.so"
		fi
		if [ ${VARIABLES_ARRAY[(i)DYLD_LIBRARY_PATH]} -le ${#VARIABLES_ARRAY} ]; then
			_bpath_auto_add_path_recursive DYLD_LIBRARY_PATH $BASE_DIRECTORY -maxdepth $SEARCH_DEPTH -name "*.dylib"
		fi
		if [ ${VARIABLES_ARRAY[(i)PKG_CONFIG_PATH]} -le ${#VARIABLES_ARRAY} ]; then
			_bpath_auto_add_path_recursive PKG_CONFIG_PATH $BASE_DIRECTORY -maxdepth $SEARCH_DEPTH -name "*.pc"
		fi

		for ENAME in $VARIABLES_ARRAY; do
			KNOWN_VARIABLES=(PATH CPATH LIBRARY_PATH LD_LIBRARY_PATH DYLD_LIBRARY_PATH PKG_CONFIG_PATH)
			if [ "$VARIABLES_OVERRIDDEN" -eq 0 -a "$ENAME" = "XDG_DATA_DIRS" ]; then
				# Never do this on our own - there is no reliable way to detect a share/
				# directory.
				continue
			fi
			if [ ${KNOWN_VARIABLES[(i)${(q)ENAME}]} -gt ${#KNOWN_VARIABLES} ]; then
				_bpath_add_path $ENAME $BASE_DIRECTORY
			fi
		done
	fi
}
