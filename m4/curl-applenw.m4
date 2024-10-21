#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
#***************************************************************************

AC_DEFUN([CURL_WITH_APPLENETWORK], [
AC_MSG_CHECKING([whether to enable Apple Network])
if test "x$OPT_APPLENETWORK" != xno; then
  if test "x$OPT_APPLENETWORK" != "xno" &&
     (test "x$cross_compiling" != "xno" || test -d "/System/Library/Frameworks/Network.framework"); then
    AC_MSG_RESULT(yes)
    AC_DEFINE(USE_APPLENW, 1, [enable Apple Network])
    AC_SUBST(USE_APPLENW, [1])
    ssl_msg="Apple Network"
    test apple-network != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
    APPLENETWORK_ENABLED=1
    LDFLAGS="$LDFLAGS -framework CoreFoundation -framework CoreServices -framework Security -framework Network"
  else
    AC_MSG_RESULT(no)
  fi
  test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"
else
  AC_MSG_RESULT(no)
fi

])
