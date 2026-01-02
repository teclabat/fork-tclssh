/*
 * gcc -shared -DUSE_TCL_STUBS -I/usr/include/tcl8.6 -L/usr/lib/tcl8.6 tclssh.c -ltclstub8.6 -lssh2 -o tclssh.so
 */
#include <libssh2.h>
#include <libssh2_sftp.h>

#ifdef HAVE_WINDOWS_H
# include <windows.h>
#endif
#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
# ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
# ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include <fcntl.h>

#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>

#include <tcl.h>


#define dprint(s,...) printf(s,##__VA_ARGS__);fflush(stdout);

static int SshSetOptionProc(ClientData instanceData, Tcl_Interp *interp, const char* optionName, const char* value);
static int SshGetOptionProc(ClientData instanceData, Tcl_Interp *interp, const char* optionName, Tcl_DString *dsPtr);
static int SshInputProc( ClientData clientData, char* buf, int bufSize, int* errorCodePtr);
static int SshOutputProc( ClientData clientData, const char* buf, int toWrite, int* errorCodePtr);
static int SshBlockModeProc( ClientData clientData, int mode);
static int SshClose2Proc( ClientData clientData, Tcl_Interp* interp, int flags);
static void SshWatchProc(ClientData instanceData, int mask);
static int SshGetHandleProc(ClientData instanceData, int direction, ClientData *handlePtr);
static int SshNotifyProc(ClientData clientData, int mask);
static void SshChannelHandler(ClientData clientData, int mask);
static void SshChannelHandlerTimer (ClientData clientData);

typedef struct State {
    Tcl_Channel self;   /* this socket channel */
    Tcl_TimerToken timer;

    int flags;          /* see State.flags above  */
    int watchMask;      /* current WatchProc mask */
    int mode;           /* current mode of parent channel */

    Tcl_Interp *interp; /* interpreter in which this resides */
    Tcl_Obj *callback;  /* script called for tracing, verifying and errors */
    Tcl_Obj *password;  /* script called for certificate password */ 

    LIBSSH2_SESSION* session;  /* libssh2 bits */
    LIBSSH2_CHANNEL* channel;
    char fingerprint[20];
    unsigned int cols, rows;

    char *err;
} State;

static Tcl_ChannelType sshChannelType = {
    "ssh",              /* Type name. */
    TCL_CHANNEL_VERSION_5,      /* v5 channel */
    TCL_CLOSE2PROC,             /* Close proc. */
    SshInputProc,               /* Input proc. */
    SshOutputProc,              /* Output proc. */
    NULL,               /* Seek proc. */
    SshSetOptionProc,           /* Set option proc. */
    SshGetOptionProc,           /* Get option proc. */
    SshWatchProc,               /* Initialize notifier. */
    SshGetHandleProc,               /* Get OS handles out of channel. */
    SshClose2Proc,              /* close2proc. */
    SshBlockModeProc,           /* Set blocking or non-blocking mode.*/
    NULL,               /* flush proc. */
    SshNotifyProc,           /* handler proc. */
    NULL,               /* wide seek proc. */
    NULL,               /* thread action proc. */
    NULL,               /* truncate proc. */
};

#define DPUTS(x) /* */
#define DPRINTF(...) /* */
/*
 *  trivial passthrough to underlying channel
 */
#ifdef PASSTHROUGH
#undef PASSTHROUGH
#endif
#define PASSTHROUGH_S(NAME, RETURN, ...) \
    DPUTS(#NAME " starting"); \
    PtyState* ps = (PtyState*)clientData; \
    Tcl_Channel channel = ps->channel; \
    int fd; \
    Tcl_GetChannelHandle(channel, TCL_READABLE|TCL_WRITABLE, (void**)&fd); \
    Tcl_Channel parent = Tcl_GetStackedChannel(channel); \
    Tcl_Driver##NAME##Proc *parentProc = Tcl_Channel##NAME##Proc(Tcl_GetChannelType(parent)); \
    if(parentProc == NULL) { \
        DPUTS(#NAME " returning error"); \
        RETURN TCL_ERROR; \
    } else { \
        if(!parent) DPUTS("parent is null!"); \
        ClientData parentData = Tcl_GetChannelInstanceData(parent); \
        if(!parentData) DPUTS("parentData is null!"); \
        DPUTS(#NAME " delegating"); \
        RETURN (*parentProc)(parentData,##__VA_ARGS__); \
    }

#define PASSTHROUGH(NAME, ...) \
    PASSTHROUGH_S(NAME, return,##__VA_ARGS__)

/**** these are based on tclpty.c */
static int
SshSetOptionProc(
    ClientData clientData,	/* File state. */
    Tcl_Interp *interp,		/* For error reporting - can be NULL. */
    const char *optionName,	/* Which option to set? */
    const char *value)		/* New value for option. */
{
    State* state = (State*)clientData;
    // int fd = ps->fd;
    Tcl_Channel channel = state->self;
    int fd;
    Tcl_GetChannelHandle(channel, TCL_READABLE|TCL_WRITABLE, (void**)&fd);

    unsigned int len = strlen(optionName);

    if((len > 4) && (strncmp(optionName, "-ptysize", len) == 0)) {
        const char **argv;
        int argc;

        if (Tcl_SplitList(interp, value, &argc, &argv) == TCL_ERROR) {
            return TCL_ERROR;
        }

        if (argc == 2) {

            int rows, cols;

            if ( (Tcl_GetInt(interp, argv[0], &cols) != TCL_OK) || (Tcl_GetInt(interp, argv[1], &rows) != TCL_OK)) {
                if (interp) {
                    Tcl_AppendResult(interp, "bad value for -ptysize: "
                            "should be a list of two integers", NULL);
                }
                ckfree((char *) argv);
                return TCL_ERROR;
            }

            // do it here
            libssh2_channel_request_pty_size(state->channel, cols, rows);
            state->cols = cols;
            state->rows = rows;

        } else {
            if (interp) {
                Tcl_AppendResult(interp, "bad value for -ptysize: "
                        "should be a list of two elements", NULL);
            }
            ckfree((char *) argv);
            return TCL_ERROR;
        }
        ckfree((char *) argv);
        return TCL_OK;
    }

    Tcl_Channel parent = Tcl_GetStackedChannel(channel);
    Tcl_DriverSetOptionProc *setOptionProc = Tcl_ChannelSetOptionProc(Tcl_GetChannelType(parent));
    if(setOptionProc == NULL) {
        return TCL_ERROR;
    }
    return setOptionProc(Tcl_GetChannelInstanceData(parent),
            interp, optionName, value);
}

static int
SshGetOptionProc(
    ClientData clientData,	/* File state. */
    Tcl_Interp *interp,		/* For error reporting - can be NULL. */
    const char *optionName,	/* Option to get. */
    Tcl_DString *dsPtr)		/* Where to store value(s). */
{
    State* state = (State*)clientData;
    // int fd = ps->fd;
    Tcl_Channel channel = state->self;
    int fd;
    Tcl_GetChannelHandle(channel, TCL_READABLE|TCL_WRITABLE, (void**)&fd);

    unsigned int len;

    if (optionName == NULL) {
        len = 0;
    } else {
        len = strlen(optionName);
    }
    if (len == 0) {
        Tcl_Channel parent = Tcl_GetStackedChannel(channel);
        Tcl_DriverGetOptionProc *getOptionProc = Tcl_ChannelGetOptionProc(Tcl_GetChannelType(parent));
        if(getOptionProc != NULL) {
            int res = getOptionProc(Tcl_GetChannelInstanceData(parent),
                    interp, optionName, dsPtr);
            if(res != TCL_OK) {
                return res;
            }
        }
    }
    if (len==0 || (len>4 && strncmp(optionName, "-fingerprint", len)==0)) {
        if(len==0) {
            Tcl_DStringAppendElement(dsPtr, "-fingerprint");
        }

        Tcl_DStringStartSublist(dsPtr);
        char buf[3];
        int i;
        for(i=0; i<20; i++) {
            sprintf(buf, "%02X", (unsigned char)state->fingerprint[i]);
            Tcl_DStringAppendElement(dsPtr, buf);
        }
        Tcl_DStringEndSublist(dsPtr);

    } else if (len==0 || (len>4 && strncmp(optionName, "-ptysize", len)==0)) {
        if(len==0) {
            Tcl_DStringAppendElement(dsPtr, "-ptysize");
        }

        char buf[5];
        Tcl_DStringStartSublist(dsPtr);
        sprintf(buf, "%u", state->cols);
        Tcl_DStringAppendElement(dsPtr, buf);
        sprintf(buf, "%u", state->rows);
        Tcl_DStringAppendElement(dsPtr, buf);
        Tcl_DStringEndSublist(dsPtr);

    } else {
        return Tcl_BadChannelOption(interp, optionName, "fingerprint ptysize");
    }
    return TCL_OK;
}

/**** these are the libssh2-heavy bits, exported commands */
int
SshImportObjCmd(
        ClientData clientData,
        Tcl_Interp *interp,
        int objc,
        Tcl_Obj *CONST objv[]
) {

    Tcl_Channel chan;
    State *state;
    int sock;

    if(objc<2) {
        Tcl_WrongNumArgs(interp, 1, objv, "channel ?options?");
        return TCL_ERROR;
    }
    chan = Tcl_GetChannel(interp, Tcl_GetStringFromObj(objv[1], NULL), NULL); 
    if (chan == (Tcl_Channel) NULL) {
        return TCL_ERROR;
    }
    Tcl_GetChannelHandle(chan, TCL_READABLE|TCL_WRITABLE, (void**)&sock);

    int idx;
    for (idx = 2; idx < objc; idx++) { 
        char *opt = Tcl_GetStringFromObj(objv[idx], NULL);
        if (opt[0] != '-') break;

        Tcl_AppendResult(interp, "bad option", NULL);
        return TCL_ERROR;
    }

    Tcl_SetChannelOption(interp, chan, "-translation", "binary");

    state = (State *) ckalloc((unsigned) sizeof(State)); 
    memset(state, 0, sizeof(State)); 
    state->interp = interp;


    state->session = libssh2_session_init();
    if (libssh2_session_handshake(state->session, sock)) {
        char *errMsg;
        libssh2_session_last_error(state->session, &errMsg, NULL, 0);
        Tcl_AppendResult(interp, "Failure establishing SSH session", errMsg, NULL);
        return TCL_ERROR;
    }
    const char *fingerprint;
    fingerprint = libssh2_hostkey_hash(state->session, LIBSSH2_HOSTKEY_HASH_SHA1);
    memcpy(state->fingerprint, fingerprint, 20);

    state->self = Tcl_StackChannel(interp, &sshChannelType, (ClientData)state, (TCL_READABLE | TCL_WRITABLE), chan);

    Tcl_SetResult(interp, (char *) Tcl_GetChannelName(state->self), TCL_VOLATILE);
    return TCL_OK;
}

/*
 * -username xxx -password xxx -pubkeyfile xxx -keyfile xxx -authcmd xxx
 */
int
SshAuthenticateObjCmd(
        ClientData clientData,
        Tcl_Interp *interp,
        int objc,
        Tcl_Obj *CONST objv[]
) {
    Tcl_Channel chan;
    State *state;
    const char *username;
    const char *password = NULL;
    const char *pubkeyfile = NULL;
    const char *keyfile = NULL;
    const char *authcmd = NULL;
    int auth_methods = 0;
    
    /** parse arguments */
    if(objc < 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "channel username ?-password xxx? ?-pubkeyfile xxx? ?-keyfile foo.key? ?-authcmd cmd?");
        return TCL_ERROR;
    }

dprint("Parsing %d args ...\n", objc);

    chan = Tcl_GetChannel(interp, Tcl_GetStringFromObj(objv[1], NULL), NULL); 
    if (chan == (Tcl_Channel) NULL) {
        Tcl_AppendResult(interp, "Invalid channel\n");
        return TCL_ERROR;
    }
    chan = Tcl_GetTopChannel(chan);
    state = (State *)Tcl_GetChannelInstanceData(chan);

    username = Tcl_GetStringFromObj(objv[2], NULL);

    int i;
    for(i=3; i<objc; ++i) {
        int len;
        const char* option = Tcl_GetStringFromObj(objv[i], &len);

        if( (len>4) && (strncmp(option, "-password", len)==0) ) {
            password = Tcl_GetStringFromObj(objv[++i], NULL);
        } else if( (len>5) && (strncmp(option, "-authcmd", len)==0) ) {
            authcmd = Tcl_GetStringFromObj(objv[++i], NULL);
        } else if( (len>4) && (strncmp(option, "-pubkeyfile", len)==0) ) {
            pubkeyfile = Tcl_GetStringFromObj(objv[++i], NULL);
        } else if( (len>4) && (strncmp(option, "-keyfile", len)==0) ) {
            keyfile = Tcl_GetStringFromObj(objv[++i], NULL);
        } else {
            Tcl_AppendResult(interp, "Invalid argument", option);
            return TCL_ERROR;
        }
    }
    if(pubkeyfile == NULL) {
        pubkeyfile = keyfile;
    }

    /** check available authentication methods */
    char* userauthlist = strdup(libssh2_userauth_list(state->session, username, strlen(username))); // FIXME: ckalloc()?
dprint("Checking auth methods against %s\n", userauthlist);

    if (strstr(userauthlist, "password") != NULL) {
        if(password) auth_methods |= 1;
    }
    if (strstr(userauthlist, "keyboard-interactive") != NULL) {
        if(authcmd) auth_methods |= 2;
    }
    if (strstr(userauthlist, "publickey") != NULL) {
        if(keyfile) auth_methods |= 4;
    }

    /** attempt authentication */
    char *errMsg;
    int err;

    if (auth_methods & 4) {
dprint("Attempting key auth using %s, %s\n", pubkeyfile, keyfile);
        if ((err = libssh2_userauth_publickey_fromfile(state->session, username, pubkeyfile, keyfile, password))) {
            libssh2_session_last_error(state->session, &errMsg, NULL, 0);
            Tcl_AppendResult(interp, "Authentication by publickey failed", errMsg, NULL);
            return TCL_ERROR;
        }
    } else if (auth_methods & 2) {
dprint("Attempting interactive auth using %s\n", keyfile);
        Tcl_AppendResult(interp, "Authentication by keyboard-interactive not supported", errMsg, NULL);
        return TCL_ERROR;
/* FIXME: requires callback
        if ((err = libssh2_userauth_keyboard_interactive(
                        state->session, username, &kbd_callback))) {
            libssh2_session_last_error(state->session, &errMsg, NULL, 0);
            Tcl_AppendResult(interp, "Authentication by keyboard-interactive failed", errMsg, NULL);
            return TCL_ERROR;
        }
 */
    } else if (auth_methods & 1) {
dprint("Attempting password auth using %s\n", keyfile);
        if ((err = libssh2_userauth_password(
                        state->session, username, password))) {
            libssh2_session_last_error(state->session, &errMsg, NULL, 0);
            Tcl_AppendResult(interp, "Authentication by password failed", errMsg, NULL);
            return TCL_ERROR;
        }
    } else {
        Tcl_AppendResult(interp, "No supported authentication methods found!", NULL);
        return TCL_ERROR;
    }

    /** start shell */
dprint("Logged in!  Opening a shell");

    if (!(state->channel = libssh2_channel_open_session(state->session))) {
        libssh2_session_last_error(state->session, &errMsg, NULL, 0);
        Tcl_AppendResult(interp, "Unable to open a channel", errMsg, NULL);
        return TCL_ERROR;
    }
    libssh2_channel_setenv(state->channel, "FOO", "bar");
    if (libssh2_channel_request_pty(state->channel, "vanilla")) {
        libssh2_session_last_error(state->session, &errMsg, NULL, 0);
        Tcl_AppendResult(interp, "Unable to request a pty", errMsg, NULL);
        return TCL_ERROR;
    }
    if (libssh2_channel_shell(state->channel)) {
        libssh2_session_last_error(state->session, &errMsg, NULL, 0);
        Tcl_AppendResult(interp, "Unable to open a shell", errMsg, NULL);
        return TCL_ERROR;
    }

    return TCL_OK;
}


/**** These are pretty simple wrappers */
static int
SshInputProc(
    ClientData clientData,
    char* buf,
    int bufSize,
    int* errorCodePtr
) {
    State *statePtr = (State *) clientData;
    int bytesRead;                      /* How many bytes were read? */
    *errorCodePtr = 0;

    bytesRead = libssh2_channel_read(statePtr->channel, buf, 4096);
    // FIXME: handle errors

    return bytesRead;
}

static int
SshOutputProc(
    ClientData clientData,
    const char* buf,
    int toWrite,
    int* errorCodePtr
) {
    State *state = (State *) clientData;
    int bytesWritten;
    *errorCodePtr = 0;
    bytesWritten = libssh2_channel_write(state->channel, buf, toWrite);
    // FIXME: handle errors
    return bytesWritten;
}

static int
SshBlockModeProc(
    ClientData clientData,
    int mode
) {
    State *state = (State *) clientData;
    libssh2_session_set_blocking(state->session, (mode == TCL_MODE_NONBLOCKING) ? 0 : 1);
    return 0;
}

static int
SshClose2Proc(
    ClientData clientData,
    Tcl_Interp* interp,
    int flags
) {
    State *state = (State *) clientData;

    Tcl_DeleteChannelHandler(state->self, SshChannelHandler, (ClientData) state);

    if(state->channel) {
        libssh2_channel_free(state->channel);
        state->channel = NULL;
    }

    if(state->session) {
        libssh2_session_disconnect(state->session, "User requested disconnect");
        libssh2_session_free(state->session);
        state->channel = NULL;
        libssh2_exit();
    }
    Tcl_EventuallyFree((ClientData)state, TCL_DYNAMIC);
    return TCL_OK;
}

/**** these are taken from tlsIO.c */
/*
 *-------------------------------------------------------------------
 *
 * SshWatchProc --
 *
 *      Initialize the notifier to watch Tcl_Files from this channel.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Sets up the notifier so that a future event on the channel
 *      will be seen by Tcl.
 *
 *-------------------------------------------------------------------
 */

static void
SshWatchProc(ClientData instanceData,   /* The socket state. */
             int mask)                  /* Events of interest; an OR-ed
                                         * combination of TCL_READABLE,
                                         * TCL_WRITABLE and TCL_EXCEPTION. */
{
    State *state = (State *) instanceData;

    //dprintf(stderr, "SshWatchProc(0x%x)\n", mask);

    if (mask == state->watchMask)
        return;

    if (state->watchMask) {
        /*
         * Remove event handler to underlying channel, this could
         * be because we are closing for real, or being "unstacked".
         */

        Tcl_DeleteChannelHandler(state->self,
                SshChannelHandler, (ClientData) state);
    }
    state->watchMask = mask;
    if (state->watchMask) {
        /*
         * Setup active monitor for events on underlying Channel.
         */

        Tcl_CreateChannelHandler(state->self,
                state->watchMask, SshChannelHandler,
                (ClientData) state);
    }
}

/*
 *-------------------------------------------------------------------
 *
 * SshGetHandleProc --
 *
 *      Called from Tcl_GetChannelFile to retrieve o/s file handler
 *      from the SSL socket based channel.
 *
 * Results:
 *      The appropriate Tcl_File or NULL if not present. 
 *
 * Side effects:
 *      None.
 *
 *-------------------------------------------------------------------
 */
static int
SshGetHandleProc(ClientData clientData,       /* The socket state. */
                 int direction,         /* Which Tcl_File to retrieve? */
                 ClientData *handlePtr) /* Where to store the handle.  */
{
    State *state = (State *) clientData;

    return Tcl_GetChannelHandle(state->self, direction, handlePtr);
}

/*
 *-------------------------------------------------------------------
 *
 * SshNotifyProc --
 *
 *      Handler called by Tcl to inform us of activity
 *      on the underlying channel.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      May process the incoming event by itself.
 *
 *-------------------------------------------------------------------
 */

static int
SshNotifyProc(ClientData instanceData, int mask)
{
    State *statePtr = (State *) instanceData;

    /*
     * An event occured in the underlying channel.  This
     * transformation doesn't process such events thus returns the
     * incoming mask unchanged.
     */

    if (statePtr->timer != (Tcl_TimerToken) NULL) {
        /*
         * Delete an existing timer. It was not fired, yet we are
         * here, so the channel below generated such an event and we
         * don't have to. The renewal of the interest after the
         * execution of channel handlers will eventually cause us to
         * recreate the timer (in WatchProc).
         */

        Tcl_DeleteTimerHandler(statePtr->timer);
        statePtr->timer = (Tcl_TimerToken) NULL;
    }

    return mask;
}

/*
 *------------------------------------------------------*
 *
 *      SshChannelHandler --
 *
 *      ------------------------------------------------*
 *      Handler called by Tcl as a result of
 *      Tcl_CreateChannelHandler - to inform us of activity
 *      on the underlying channel.
 *      ------------------------------------------------*
 *
 *      Sideeffects:
 *              May generate subsequent calls to
 *              Tcl_NotifyChannel.
 *
 *      Result:
 *              None.
 *
 *------------------------------------------------------*
 */

static void
SshChannelHandler(ClientData clientData, int mask)
{
    State *statePtr = (State *) clientData;

//dprintf(stderr, "HANDLER(0x%x)\n", mask);
    Tcl_Preserve( (ClientData)statePtr);

    /*
     * The following NotifyChannel calls seems to be important, but
     * we don't know why.  It looks like if the mask is ever non-zero
     * that it will enter an infinite loop.
     *
     * Notify the upper channel of the current BIO state so the event
     * continues to propagate up the chain.
     *
     * stanton: It looks like this could result in an infinite loop if
     * the upper channel doesn't cause ChannelHandler to be removed
     * before Tcl_NotifyChannel calls channel handlers on the lower channel.
     */
    
    Tcl_NotifyChannel(statePtr->self, mask);
    
    if (statePtr->timer != (Tcl_TimerToken)NULL) {
        Tcl_DeleteTimerHandler(statePtr->timer);
        statePtr->timer = (Tcl_TimerToken)NULL;
    }
    if ((mask & TCL_READABLE) && Tcl_InputBuffered(statePtr->self) > 0) {
        /*
         * Data is waiting, flush it out in short time
         */
        statePtr->timer = Tcl_CreateTimerHandler(5,
                SshChannelHandlerTimer, (ClientData) statePtr);
    }
    Tcl_Release( (ClientData)statePtr);
}

/*
 *------------------------------------------------------*
 *
 *      SshChannelHandlerTimer --
 *
 *      ------------------------------------------------*
 *      Called by the notifier (-> timer) to flush out
 *      information waiting in channel buffers.
 *      ------------------------------------------------*
 *
 *      Sideeffects:
 *              As of 'SshChannelHandler'.
 *
 *      Result:
 *              None.
 *
 *------------------------------------------------------*
 */

static void
SshChannelHandlerTimer (ClientData clientData)
{
    State *statePtr = (State *) clientData;
    int mask = 0;

    statePtr->timer = (Tcl_TimerToken) NULL;

    Tcl_NotifyChannel(statePtr->self, mask);
}

Tcl_Channel
Tls_GetParent( State *state)
{
    return Tcl_GetStackedChannel(state->self);
}




/**** Inititalise extension */
int
Tclssh2_Init(Tcl_Interp *interp)
{
    if (Tcl_InitStubs(interp, "8.5", 0) == NULL) {
        return TCL_ERROR;
    }
    if (Tcl_PkgRequire(interp, "Tcl", "8.5", 0) == NULL) {
        return TCL_ERROR;
    }
    if (Tcl_PkgProvide(interp, "tclssh2", "0.1") != TCL_OK) {
        return TCL_ERROR;
    }

    Tcl_CreateObjCommand(interp, "ssh::import",
            (Tcl_ObjCmdProc *)SshImportObjCmd,
            (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    Tcl_CreateObjCommand(interp, "ssh::authenticate",
            (Tcl_ObjCmdProc *)SshAuthenticateObjCmd,
            (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);

    return TCL_OK;
}
