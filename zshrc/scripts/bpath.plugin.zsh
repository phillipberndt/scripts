# bpath: Add local prefix to influential environment variables
#
# By default, mpath tries to perform some magic to autodetermine what to add
# where. Alternatively, you can supply it with the name of an environment
# variable and parameters to `find'. It will append all directories of the
# files found by find to the variable. If you issue bpath NAME, then the
# current directory will be added to $NAME.

bpath() {
	_add_path() {
		NAMES=$1
		VALUE=$(readlink -f "$2" 2>/dev/null)

		if [ ! -d "$VALUE" ]; then
			return
		fi

		NAMES_ARRAY=("${(@s/:/)NAMES}")
		for NAME in $NAMES_ARRAY; do
			eval export $NAME

			echo -e "\033[1m$NAME\033[0m += ( \033[32m$VALUE\033[0m )"

			if [ -n "${(P)NAME}" ]; then
				if [ "${(P)NAME/${VALUE}:/}" = "${(P)NAME}" ]; then
					eval ${NAME}=\$VALUE:\$$NAME
				fi
			else
				eval ${NAME}=\$VALUE
			fi
		done
	}

	_auto_add_path_recursive() {
		NAME=$1
		BASE=$2
		shift 2

		NAMES_ARRAY=("${(@s/:/)NAME}")
		for ENAME in $NAMES_ARRAY; do
			eval export $ENAME
		done

		while read P; do
			_add_path $NAME $P
		done < <(find $BASE $@ -printf "%h\n" | sort | uniq)
	}

	export PATH
	export CPATH
	export LIBRARY_PATH
	export PKG_CONFIG_PATH
	export XDG_DATA_DIRS

	if [ "$#" -gt 0 ]; then
		if [ "$1" = "-h" ]; then
			echo "bpath: Add local prefix to influential environment variables"
			echo
			echo "By default, mpath tries to perform some magic to autodetermine what to"
			echo "add where. Alternatively, you can supply it with the name of an environment"
			echo "variable and parameters to \`find'. It will append all directories of the"
			echo "files found by find to the variable. If you issue bpath NAME, then the current"
			echo "directory will be added to \$NAME."
			echo
			return
		fi
		eval export $1
		if [ "$#" -eq 1 ]; then
			_add_path $1 .
		else
			_auto_add_path_recursive $@
		fi
	elif [ -d bin -o -d lib -o -d include -o -d share ]; then
		_add_path PATH bin
		_auto_add_path_recursive CPATH include -maxdepth 2 -name "*.h"
		_auto_add_path_recursive LIBRARY_PATH:LD_LIBRARY_PATH lib -maxdepth 2 "(" -name "*.so" -o -name "*.a" -o -name "*.la" ")"
		_add_path PKG_CONFIG_PATH lib/pkgconfig
		_add_path XDG_DATA_DIRS share
	else
		_auto_add_path_recursive PATH . -maxdepth 3 -executable
		_auto_add_path_recursive CPATH . -maxdepth 3  -name "*.h"
		_auto_add_path_recursive LIBRARY_PATH:LD_LIBRARY_PATH . -maxdepth 3 "(" -name "*.so" -o -name "*.a" -o -name "*.la" ")"
		_auto_add_path_recursive PKG_CONFIG_PATH . -maxdepth 3 -name "*.pc"
	fi
}
