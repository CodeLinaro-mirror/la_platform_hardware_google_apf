#!/bin/bash
set -e
set -u

do_assemble() {
  local -r RE='^#include "([a-z_]+[.]h)"$'

  local line
  while IFS='' read -r line; do
    if [[ "${line}" =~ ${RE} ]]; then
      local include_name="${BASH_REMATCH[1]}"
      case "${include_name}" in
        apf_interpreter.h)
          echo "#include \"${BASH_REMATCH[1]}\""
          ;;
        *)
          echo "/* Begin include of ${include_name} */"
          cat "${include_name}"
          echo "/* End include of ${include_name} */"
          ;;
      esac
    else
      echo "${line}"
    fi
  done < apf_interpreter_source.c \
  | sed -r 's@(^|[^:])//(.*)$@\1/*\2 */@'
  # The above sed converts // comments into /* */ comments for c89
}

do_test() {
  diff -q <(do_assemble) apf_interpreter.c
}

main() {
  cd "${0%/*}"

  local -r me="${0##*/}"
  case "${me}" in
    apf_interpreter_assemble.sh)
      do_assemble > apf_interpreter.c
      ;;
    apf_assemble_test.sh)
      do_test
      ;;
    *)
      echo "Unknown $0" 1>&2
      return 1
      ;;
  esac
}

main "$@"; exit
