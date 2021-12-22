[[ -o interactive ]] || return 0

__lf() {
	local o
	local d
	o="$(tempfile)"
	trap "rm ${(q)o}" EXIT
	lf -last-dir-path "$o"
    zle redisplay
	zle push-line
	d="$(cat "$o")"
	BUFFER="cd -- ${(q)d}"
	zle accept-line
	zle reset-prompt
    return 0
}
zle     -N    __lf
bindkey '\er' __lf
