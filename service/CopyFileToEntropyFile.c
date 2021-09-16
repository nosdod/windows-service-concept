/*--------------------------------------------------------------------------
MODULE:   CopyFileToEntropy.c

PURPOSE:  Implements the body of the service.
          The default behavior is to open a
          named pipe, \\.\pipe\copyfiletoentropy, 
          Then wait for writes to occur on the pipe.
          When a write occurs it will
             Read the string expecting it to be a filename
             Acknowledge the request back to the pipe.
             It logs the request
             It then copies the contents of that file 
             to the configured entropy file, overwriting its current contents.
             It logs the result of the write operation.
             It then writes back to the pipe the result of the operation.

FUNCTIONS:
          ServiceStart(DWORD dwArgc, LPTSTR *lpszArgv);
          ServiceStop( );

COMMENTS: The functions implemented in CopyFileToEntropy.c are
          prototyped in service.h
--------------------------------------------------------------------------*/


#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h>
#include <tchar.h>
#include "service.h"
#include "utilities.h"
#include <strsafe.h>

// Internal variables
TCHAR    szErr[256]; // Holds an error message

// this event is signalled when the
// service should end
//
HANDLE  hServerStopEvent = NULL;

// CreateMyDACL
// Creates a security descriptor containing the
// desired DACL. This function uses SDDL to make Deny and Allow ACEs.
//
// Parameter:
//     SECURITY_ATTRIBUTES * pSA
// Address to a SECURITY_ATTRIBUTES structure. It is the caller's
// responsibility to properly initialize the structure, and to free 
// the structure's lpSecurityDescriptor member when done (by calling
// the LocalFree function).
// 
// Return value:
//    FALSE if the address to the structure is NULL. 
//    Otherwise, this function returns the value from the
//    ConvertStringSecurityDescriptorToSecurityDescriptor function.
BOOL CreateMyDACL(SECURITY_ATTRIBUTES * pSA)
{
    // Define the SDDL for the DACL. This example sets 
    // the following access:
    //     Built-in guests are denied all access.
    //     Anonymous Logon is denied all access.
    //     Authenticated Users are allowed read/write/execute access.
    //     Administrators are allowed full control.
    // Modify these values as needed to generate the proper
    // DACL for your application. 
    TCHAR * szSD = "D:"                   // Discretionary ACL
                   "(D;OICI;GA;;;BG)"     // Deny access to Built-in Guests
                   "(D;OICI;GA;;;AN)"     // Deny access to Anonymous Logon
                   "(A;OICI;GRGWGX;;;AU)" // Allow read/write/execute to Authenticated Users
                   "(A;OICI;GA;;;BA)";    // Allow full control to Administrators

    if (NULL == pSA)
        return FALSE;

    return ConvertStringSecurityDescriptorToSecurityDescriptor(
                                                              szSD,
                                                              SDDL_REVISION_1,
                                                              &(pSA->lpSecurityDescriptor),
                                                              NULL);
}


//
//  FUNCTION: ServiceStart
//
//  PURPOSE: Actual code of the service that does the work.
//
//  PARAMETERS:
//    dwArgc   - number of command line arguments
//    lpszArgv - array of command line arguments
//
//  RETURN VALUE:
//    none
//
//  COMMENTS:
//    The default behavior is to open a
//    named pipe, \\.\pipe\simple, and read
//    from it.  It the modifies the data and
//    writes it back to the pipe.  The service
//    stops when hServerStopEvent is signalled
//
VOID ServiceStart (DWORD dwArgc, LPTSTR *lpszArgv)
{
   HANDLE                  hPipe = INVALID_HANDLE_VALUE;
   HANDLE                  hEvents[2] = {NULL, NULL};
   OVERLAPPED              os;
   PSECURITY_DESCRIPTOR    pSD = NULL;
   SECURITY_ATTRIBUTES     sa;
   TCHAR                   szIn[80];
   TCHAR                   szOut[ (sizeof(szIn) / sizeof(TCHAR) )  + 100];
   LPTSTR                  lpszPipeName = TEXT("\\\\.\\pipe\\copyfiletoentropyfile");
   BOOL                    bRet;
   DWORD                   cbRead;
   DWORD                   cbWritten;
   DWORD                   dwWait;
   UINT                    ndx;

   ///////////////////////////////////////////////////
   //
   // Service initialization
   //

   // report the status to the service control manager.
   //
   if (!ReportStatusToSCMgr(
                           SERVICE_START_PENDING, // service state
                           NO_ERROR,              // exit code
                           3000))                 // wait hint
      goto cleanup;

   // create the event object. The control handler function signals
   // this event when it receives the "stop" control code.
   //
   hServerStopEvent = CreateEvent(
                                 NULL,    // no security attributes
                                 TRUE,    // manual reset event
                                 FALSE,   // not-signalled
                                 NULL);   // no name

   if ( hServerStopEvent == NULL)
      goto cleanup;

   hEvents[0] = hServerStopEvent;

   // report the status to the service control manager.
   //
   if (!ReportStatusToSCMgr(
                           SERVICE_START_PENDING, // service state
                           NO_ERROR,              // exit code
                           3000))                 // wait hint
      goto cleanup;

   // create the event object object use in overlapped i/o
   //
   hEvents[1] = CreateEvent(
                           NULL,    // no security attributes
                           TRUE,    // manual reset event
                           FALSE,   // not-signalled
                           NULL);   // no name

   if ( hEvents[1] == NULL)
      goto cleanup;

   // report the status to the service control manager.
   //
   if (!ReportStatusToSCMgr(
                           SERVICE_START_PENDING, // service state
                           NO_ERROR,              // exit code
                           3000))                 // wait hint
      goto cleanup;

   // create a security descriptor that allows anyone to write to
   //  the pipe...
   //
   pSD = (PSECURITY_DESCRIPTOR) malloc( SECURITY_DESCRIPTOR_MIN_LENGTH );

   if (pSD == NULL)
      goto cleanup;

   if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
      goto cleanup;

   sa.nLength = sizeof(sa);
   sa.bInheritHandle = TRUE;
   sa.lpSecurityDescriptor = pSD;

   if(!CreateMyDACL(&sa) )
   {
       // DACL creation FAILED!!
       return;
   }

   // report the status to the service control manager.
   //
   if (!ReportStatusToSCMgr(
                           SERVICE_START_PENDING, // service state
                           NO_ERROR,              // exit code
                           3000))                 // wait hint
      goto cleanup;


   // allow user tp define pipe name
   for ( ndx = 1; ndx < dwArgc-1; ndx++ )
   {

      if ( ( (*(lpszArgv[ndx]) == TEXT('-')) ||
             (*(lpszArgv[ndx]) == TEXT('/')) ) &&
           (!_tcsicmp( TEXT("pipe"), lpszArgv[ndx]+1 ) && ((ndx + 1) < dwArgc)) )
      {
         lpszPipeName = lpszArgv[++ndx];
      }

   }

   // open our named pipe...
   //
   hPipe = CreateNamedPipe(
                          lpszPipeName         ,  // name of pipe
                          FILE_FLAG_OVERLAPPED |
                          PIPE_ACCESS_DUPLEX,     // pipe open mode
                          PIPE_TYPE_MESSAGE |
                          PIPE_READMODE_MESSAGE |
                          PIPE_WAIT,              // pipe IO type
                          1,                      // number of instances
                          0,                      // size of outbuf (0 == allocate as necessary)
                          0,                      // size of inbuf
                          1000,                   // default time-out value
                          &sa);                   // security attributes

   if (hPipe == INVALID_HANDLE_VALUE)
   {
      AddToMessageLog(TEXT("Unable to create named pipe"));
      goto cleanup;
   }


   // report the status to the service control manager.
   //
   if (!ReportStatusToSCMgr(
                           SERVICE_RUNNING,       // service state
                           NO_ERROR,              // exit code
                           0))                    // wait hint
      goto cleanup;

   //
   // End of initialization
   //
   ////////////////////////////////////////////////////////

   ////////////////////////////////////////////////////////
   //
   // Service is now running, perform work until shutdown
   //

   for(;;)
   {
      // init the overlapped structure
      //
      memset( &os, 0, sizeof(OVERLAPPED) );
      os.hEvent = hEvents[1];
      ResetEvent( hEvents[1] );


      // wait for a connection...
      //
      ConnectNamedPipe(hPipe, &os);

      if ( GetLastError() == ERROR_IO_PENDING )
      {
         dwWait = WaitForMultipleObjects( 2, hEvents, FALSE, INFINITE );
         if ( dwWait != WAIT_OBJECT_0+1 )     // not overlapped i/o event - error occurred,
            break;                           // or server stop signaled
      }

      // init the overlapped structure
      //
      memset( &os, 0, sizeof(OVERLAPPED) );
      os.hEvent = hEvents[1];
      ResetEvent( hEvents[1] );


     // Set the buffer to all NULLs otherwise we get leftover characters
      memset(szIn, '\0', sizeof(szIn));

      // grab whatever's coming through the pipe...
      //
      bRet = ReadFile(
                     hPipe,          // file to read from
                     szIn,           // address of input buffer
                     sizeof(szIn),   // number of bytes to read
                     &cbRead,        // number of bytes read
                     &os);           // overlapped stuff, not needed

      if ( !bRet && ( GetLastError() == ERROR_IO_PENDING ) )
      {
         dwWait = WaitForMultipleObjects( 2, hEvents, FALSE, INFINITE );
         if ( dwWait != WAIT_OBJECT_0+1 )     // not overlapped i/o event - error occurred,
            break;                           // or server stop signaled
      }

      BOOL bOperationFailed = FALSE;
      WIN32_FIND_DATA FileData;
      HANDLE          hSearch;
      DWORD           dwAttrs;
      TCHAR           szNewPath[MAX_PATH];
      TCHAR           szOldPath[MAX_PATH];
      TCHAR           szDest[MAX_PATH];
      TCHAR           szSearch[MAX_PATH];
      TCHAR           szFailureMsg[256];
      INT             iFileCount = 0;

      BOOL            fFinished = FALSE;

      // Set the destination
      // TODO : Make this a configurable item
      StringCchPrintf(szDest, sizeof(szDest) / sizeof(szDest[0]), TEXT("C:\\Users\\markd\\Documents\\entropy"));

      // Check the destination is accessible
      dwAttrs = GetFileAttributes(szDest);
      if (dwAttrs == INVALID_FILE_ATTRIBUTES) {
          bOperationFailed = TRUE;
          StringCchPrintf(szFailureMsg, sizeof(szFailureMsg) / sizeof(szFailureMsg[0]), TEXT("ERROR : Destination [%s] is an invalid location"), szDest);
      }
      else { // Is a valid File/Dir
          if (!(dwAttrs & FILE_ATTRIBUTE_DIRECTORY))
          {
              bOperationFailed = TRUE;
              StringCchPrintf(szFailureMsg, sizeof(szFailureMsg) / sizeof(szFailureMsg[0]), TEXT("ERROR : Destination [%s] must be a directory"), szDest);
          }
          else { // Is a directory
              if (dwAttrs & FILE_ATTRIBUTE_READONLY)
              {
                  bOperationFailed = TRUE;
                  StringCchPrintf(szFailureMsg, sizeof(szFailureMsg) / sizeof(szFailureMsg[0]), TEXT("ERROR : Destination [%s] must be writeable"), szDest);
              }
          }
      }

      if (!bOperationFailed)
      {
          // Set the search location
          StringCchPrintf(szSearch, sizeof(szSearch) / sizeof(szSearch[0]), TEXT("%s\\*"), szIn);

          hSearch = FindFirstFile(szSearch, &FileData);
          if (hSearch == INVALID_HANDLE_VALUE)
          {
              //printf("No text files found.\n");
              bOperationFailed = TRUE;
              StringCchPrintf(szFailureMsg, sizeof(szFailureMsg) / sizeof(szFailureMsg[0]), TEXT("ERROR : No files found matching [%s]"), szIn);
          }

          // Copy each file to the new directory 
          // and change it to read only, if not already. 

          // Target fixed as in this example
          while (!bOperationFailed && !fFinished)
          {
              if (FileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
              {
                  // Ignore directories
              }
              else {
                  StringCchPrintf(szNewPath, sizeof(szNewPath) / sizeof(szNewPath[0]), TEXT("%s\\%s"),szDest, FileData.cFileName);

                  StringCchPrintf(szOldPath, sizeof(szOldPath) / sizeof(szOldPath[0]), TEXT("%s\\%s"), szIn, FileData.cFileName);
                  if (CopyFile(szOldPath, szNewPath, FALSE))
                  {
                      dwAttrs = GetFileAttributes(szNewPath);
                      if (dwAttrs == INVALID_FILE_ATTRIBUTES) {
                          bOperationFailed = TRUE;
                          StringCchPrintf(szFailureMsg, sizeof(szFailureMsg) / sizeof(szFailureMsg[0]), TEXT("ERROR : Could not get attributes of file [%s]"), szNewPath);
                      }
                      else {
                          if (dwAttrs & FILE_ATTRIBUTE_READONLY)
                          {
                              // Remove the READ ONLY attribute
                              if (!SetFileAttributes(szNewPath, FILE_ATTRIBUTE_NORMAL)) {
                                  //printf("Could not change file to read only.\n");
                                  bOperationFailed = TRUE;
                                  StringCchPrintf(szFailureMsg, sizeof(szFailureMsg) / sizeof(szFailureMsg[0]), TEXT("ERROR : Could not remove read only from file [%s]"), szNewPath);
                              };
                          }
                          iFileCount++;
                      }
                  }
                  else
                  {
                      //printf("Could not copy file.\n");
                      bOperationFailed = TRUE;
                      StringCchPrintf(szFailureMsg, sizeof(szFailureMsg) / sizeof(szFailureMsg[0]), TEXT("ERROR : Could not copy file [%s] to [%s]"), szOldPath,szNewPath);
                  }
              }

              if (!bOperationFailed && !FindNextFile(hSearch, &FileData))
              {
                  if (GetLastError() == ERROR_NO_MORE_FILES)
                  {
                      //_tprintf(TEXT("Copied *.txt to %s\n"), argv[1]);
                      fFinished = TRUE;
                  }
                  else
                  {
                      //printf("Could not find next file.\n");
                      bOperationFailed = TRUE;
                      StringCchPrintf(szFailureMsg, sizeof(szFailureMsg) / sizeof(szFailureMsg[0]), TEXT("ERROR : Could not find next file"));
                  }
              }
          }

          // Close the search handle. 

          FindClose(hSearch);

      }
      // Respond with status of all operations
      if (bOperationFailed) {
          // Retrieve the system error message for the last-error code
          StringCchPrintf(szOut, sizeof(szOut), TEXT("[ERROR] %s [%s]"), szFailureMsg, GetLastErrorText(szErr,256));
      }
      else {
          StringCchPrintf(szOut, sizeof(szOut), TEXT("[INFO] %d files copied to %s"),iFileCount,szDest );
      }

      // init the overlapped structure
      //
      memset(&os, 0, sizeof(OVERLAPPED));
      os.hEvent = hEvents[1];
      ResetEvent(hEvents[1]);

      // send out the acknowledgement ...
      //
      bRet = WriteFile(
          hPipe,          // file to write to
          szOut,          // address of output buffer
          sizeof(szOut),  // number of bytes to write
          &cbWritten,     // number of bytes written
          &os);           // overlapped stuff, not needed


      if (!bRet && (GetLastError() == ERROR_IO_PENDING))
      {
          dwWait = WaitForMultipleObjects(2, hEvents, FALSE, INFINITE);
          if (dwWait != WAIT_OBJECT_0 + 1)     // not overlapped i/o event - error occurred,
              break;                           // or server stop signaled
      }

      // drop the connection...
      //
      DisconnectNamedPipe(hPipe);
   }

   cleanup:

   if (hPipe != INVALID_HANDLE_VALUE )
      CloseHandle(hPipe);

   if (hServerStopEvent)
      CloseHandle(hServerStopEvent);

   if (hEvents[1]) // overlapped i/o event
      CloseHandle(hEvents[1]);

   if ( pSD )
      free( pSD );

}


//
//  FUNCTION: ServiceStop
//
//  PURPOSE: Stops the service
//
//  PARAMETERS:
//    none
//
//  RETURN VALUE:
//    none
//
//  COMMENTS:
//    If a ServiceStop procedure is going to
//    take longer than 3 seconds to execute,
//    it should spawn a thread to execute the
//    stop code, and return.  Otherwise, the
//    ServiceControlManager will believe that
//    the service has stopped responding.
//
VOID ServiceStop()
{
   if ( hServerStopEvent )
      SetEvent(hServerStopEvent);
}
