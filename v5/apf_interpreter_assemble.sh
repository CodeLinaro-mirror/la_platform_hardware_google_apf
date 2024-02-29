#!/bin/bash
set -e
set -u

do_assemble() {
  local -r RE_INCLUDE='^#include "([a-z_]+[.]h)"$'
  local -r RE_UNDEF='^#undef ([_A-Za-z0-9]+)$'
  local -r RE_DEFINE='^#define ([_A-Za-z0-9]+) (.*)$'

  local line
  while IFS='' read -r line; do
    if [[ "${line}" =~ ${RE_INCLUDE} ]]; then
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
    elif [[ "${line}" =~ ${RE_UNDEF} ]]; then
      case "${BASH_REMATCH[1]}" in
        bool|true|false) : ;;
        *) echo "${line}" ;;
      esac
    elif [[ "${line}" =~ ${RE_DEFINE} ]]; then
      case "${BASH_REMATCH[1]}" in
        bool|true|false) : ;;
        *) echo "${line}" ;;
      esac
    else
      echo "${line}"
    fi
  done < apf_interpreter_source.c \
  | sed -r \
's@(^|[^:])//(.*)$@\1/*\2 */@;'\
's@(^|[^A-Za-z0-9_])bool([^A-Za-z0-9_]|$)@\1Boolean\2@g;'\
's@(^|[^A-Za-z0-9_])true([^A-Za-z0-9_]|$)@\1True\2@g;'\
's@(^|[^A-Za-z0-9_])false([^A-Za-z0-9_]|$)@\1False\2@g;'
  # The above sed converts // comments into /* */ comments for c89,
  # and converts bool/true/false into Boolean/True/False
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
