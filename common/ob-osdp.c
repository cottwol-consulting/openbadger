/*
  Copyright 2026 Cottwol Consulting

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>


#include <jansson.h>


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <openbadger-common.h>


int ob_command_osdp
  (OB_CONTEXT *ctx,
  char *command)

{ /* ob_command */

  struct sockaddr_un addr;
  int fd;
  char socket_path [1024];
  int status;
  int status_io;


  status = ST_OK;
  sprintf(socket_path, "/opt/osdp-conformance/run/ACU/open-osdp-control");
  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd EQUALS -1)
    status = STOB_OSDP_SOCKET;
  if (status EQUALS ST_OK)
  {
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);
    status_io = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (status_io EQUALS -1)
    {
      status = STOB_OSDP_CONNECT;
    };
  };
  if (status EQUALS ST_OK)
  {
    status_io = write(fd, command, 1+strlen(command)); // write the null
    if (status_io EQUALS -1)
      status = STOB_OSDP_SOCK_WRITE;
  };

  return(status);

} /* ob_command */

