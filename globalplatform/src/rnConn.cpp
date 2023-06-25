/*  Copyright (c) 2009, Karsten Ohme
 *  This file is part of GlobalPlatform.
 *
 *  GlobalPlatform is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GlobalPlatform is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with GlobalPlatform.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "globalplatform/connection.h"
#include "globalplatform/globalplatform.h"
#include "globalplatform/debug.h"
#include "globalplatform/stringify.h"
#include "globalplatform/error.h"
#include "crypto.h"
#include <string.h>

static DWORD traceEnable = false;  //!< Enable trace mode.
static FILE* traceFile = nullptr;  //!< The trace file for trace mode.

/**
 * If the transmission is successful then the APDU status word is returned as
 * errorCode in the OPGP_ERROR_STATUS structure. \param cardContext [in] The
 * valid OPGP_CARD_CONTEXT returned by OPGP_establish_context() \param cardInfo
 * [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect(). \param
 * *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned
 * by GP211_mutual_authentication(). \param capdu [in] The command APDU. \param
 * capduLength [in] The length of the command APDU. \param rapdu [out] The
 * response APDU. \param rapduLength [in, out] The length of the response APDU.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS
 * if no error occurs, otherwise error code and error message are contained in
 * the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_send_APDU(OPGP_CARD_CONTEXT cardContext,
                                 OPGP_CARD_INFO cardInfo,
                                 GP211_SECURITY_INFO* secInfo, PBYTE capdu,
                                 DWORD capduLength, PBYTE rapdu,
                                 PDWORD rapduLength) {
  OPGP_ERROR_STATUS errorStatus;
  OPGP_ERROR_STATUS(*plugin_sendAPDUFunction)
  (OPGP_CARD_CONTEXT, OPGP_CARD_INFO, PBYTE, DWORD, PBYTE, PDWORD);
  BYTE apduCommand[APDU_COMMAND_LEN];
  DWORD apduCommandLength = APDU_COMMAND_LEN;
  DWORD errorCode;
  int i = 0;

  OPGP_LOG_START(_T("OPGP_send_APDU"));
  plugin_sendAPDUFunction = (OPGP_ERROR_STATUS(*)(
      OPGP_CARD_CONTEXT, OPGP_CARD_INFO, PBYTE, DWORD, PBYTE,
      PDWORD))cardContext.connectionFunctions.sendAPDU;

  OPGP_LOG_HEX(_T("OPGP_send_APDU: Command --> "), capdu, capduLength);

  if (traceEnable) {
    _ftprintf(traceFile, _T("Command --> "));
    for (i = 0; (DWORD)i < capduLength; i++) {
      _ftprintf(traceFile, _T("%02X"), capdu[i] & 0x00FF);
    }
    _ftprintf(traceFile, _T("\n"));
  }

  // wrap command
  errorStatus = wrap_command(capdu, capduLength, apduCommand,
                             &apduCommandLength, secInfo);
  if (OPGP_ERROR_CHECK(errorStatus)) {
    goto end;
  }

  capdu[0] |= cardInfo.logicalChannel;

  if (traceEnable) {
    _ftprintf(traceFile, _T("Wrapped command --> "));
    for (i = 0; (DWORD)i < apduCommandLength; i++) {
      _ftprintf(traceFile, _T("%02X"), apduCommand[i] & 0x00FF);
    }
    _ftprintf(traceFile, _T("\n"));
  }

  /* AC Bugfix: Don't attempt to call function if fpointer is null */
  if (plugin_sendAPDUFunction == NULL) {
    OPGP_ERROR_CREATE_ERROR(
        errorStatus, 0,
        _T("sendAPDUFunction is NULL. Likely no connection library is set."));
    goto end;
  } else {
    errorStatus =
        (*plugin_sendAPDUFunction)(cardContext, cardInfo, apduCommand,
                                   apduCommandLength, rapdu, rapduLength);
    if (OPGP_ERROR_CHECK(errorStatus)) {
      goto end;
    }
    errorCode = errorStatus.errorCode;
  }

  OPGP_LOG_HEX(_T("OPGP_send_APDU: Response <-- "), rapdu, *rapduLength);

  if (traceEnable) {
    _ftprintf(traceFile, _T("Response <-- "));
    for (i = 0; (DWORD)i < *rapduLength; i++) {
      _ftprintf(traceFile, _T("%02X"), rapdu[i] & 0x00FF);
    }
    _ftprintf(traceFile, _T("\n"));
  }

  errorStatus = unwrap_command(capdu, capduLength, rapdu, *rapduLength, rapdu,
                               rapduLength, secInfo);
  if (OPGP_ERROR_CHECK(errorStatus)) {
    goto end;
  }
  // add code from sendAPDUFunction again
  errorStatus.errorCode = errorCode;
  if (traceEnable) {
    _ftprintf(traceFile, _T("Unwrapped response <-- "));
    for (i = 0; (DWORD)i < *rapduLength; i++) {
      _ftprintf(traceFile, _T("%02X"), rapdu[i] & 0x00FF);
    }
    _ftprintf(traceFile, _T("\n"));
  }

end:
  OPGP_LOG_END(_T("OPGP_send_APDU"), errorStatus);
  return errorStatus;
}
