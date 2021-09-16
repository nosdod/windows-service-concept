#include <windows.h>
#include <stdio.h>
#include <tchar.h>

//
//  FUNCTION: GetLastErrorText
//
//  PURPOSE: copies error message text to string
//
//  PARAMETERS:
//    lpszBuf - destination buffer
//    dwSize - size of buffer
//
//  RETURN VALUE:
//    destination buffer
//
//  COMMENTS:
//
LPTSTR GetLastErrorText(LPTSTR lpszBuf, DWORD dwSize)
{
    DWORD dwRet;
    LPTSTR lpszTemp = NULL;

    dwRet = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ARGUMENT_ARRAY,
        NULL,
        GetLastError(),
        LANG_NEUTRAL,
        (LPTSTR)&lpszTemp,
        0,
        NULL);

    // supplied buffer is not long enough
    if (!dwRet || ((long)dwSize < (long)dwRet + 14))
        lpszBuf[0] = TEXT('\0');
    else
    {
        if (NULL != lpszTemp)
        {
            lpszTemp[lstrlen(lpszTemp) - 2] = TEXT('\0');  //remove cr and newline character
            _stprintf_s(lpszBuf, dwSize, TEXT("%s (0x%x)"), lpszTemp, GetLastError());
        }
    }

    if (NULL != lpszTemp)
        LocalFree((HLOCAL)lpszTemp);

    return lpszBuf;
}