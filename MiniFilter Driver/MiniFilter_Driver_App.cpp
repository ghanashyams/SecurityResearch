#include <fltKernel.h>

// ---------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------
PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT   gServerPort   = NULL;
PFLT_PORT   gClientPort   = NULL;

// Guards gClientPort against concurrent connect/disconnect/use.
// A fast mutex is appropriate here: FltSendMessage runs at PASSIVE_LEVEL,
// so this is safe to hold across it (unlike a spinlock, which would raise
// IRQL and forbid the wait inside FltSendMessage).
FAST_MUTEX gClientPortLock;

// Cap scan payload to fit within UserApp.cpp's fixed 4096-byte receive
// buffer, minus the FILTER_MESSAGE_HEADER and SCAN_MESSAGE header that
// FltSendMessage/FilterGetMessage prepend/contain.
#define MAX_SCAN_DATA \
    (4096 - sizeof(FILTER_MESSAGE_HEADER) - FIELD_OFFSET(SCAN_MESSAGE, Data))

// Reasonable upper bound on how long we'll wait for the user-mode
// scanner before failing open/closed (see FAIL_OPEN_ON_TIMEOUT below).
// 5 seconds; tune to your product's latency budget.
#define SCAN_TIMEOUT_MS (5 * 1000)

// Security policy on scanner timeout/failure: TRUE = allow the write
// through (favors availability), FALSE = block it (favors security).
// Real products often make this configurable; hardcoded here for clarity.
#define FAIL_OPEN_ON_TIMEOUT TRUE

typedef struct _SCAN_MESSAGE {
    ULONG Length;      // number of bytes actually present in Data
    UCHAR Data[1];      // variable length -- struct is allocated with
                        // extra trailing bytes; never stack-allocate this
} SCAN_MESSAGE, *PSCAN_MESSAGE;

typedef struct _SCAN_REPLY {
    BOOLEAN Allow; // TRUE = allow, FALSE = block
} SCAN_REPLY, *PSCAN_REPLY;

#define SCAN_POOL_TAG 'nacS' // "Scan" -- shows up in pool tag tools for leak triage

// ---------------------------------------------------------------------
// Communication port callbacks
// ---------------------------------------------------------------------
NTSTATUS ConnectNotify(PFLT_PORT ClientPort, PVOID ServerPortCookie,
                       PVOID ConnectionContext, ULONG SizeOfContext,
                       PVOID *ConnectionPortCookie) {
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);

    ExAcquireFastMutex(&gClientPortLock);
    if (gClientPort != NULL) {
        // A client is already connected (MaxConnections=1 should already
        // prevent this, but guard explicitly rather than silently
        // clobbering an existing legitimate connection).
        ExReleaseFastMutex(&gClientPortLock);
        DbgPrint("Rejecting second connection attempt\n");
        return STATUS_CONNECTION_ACTIVE;
    }
    gClientPort = ClientPort;
    ExReleaseFastMutex(&gClientPortLock);

    DbgPrint("User-mode scanner connected\n");
    return STATUS_SUCCESS;
}

VOID DisconnectNotify(PVOID ConnectionCookie) {
    UNREFERENCED_PARAMETER(ConnectionCookie);

    ExAcquireFastMutex(&gClientPortLock);
    if (gClientPort) {
        FltCloseClientPort(gFilterHandle, &gClientPort);
        gClientPort = NULL;
    }
    ExReleaseFastMutex(&gClientPortLock);

    DbgPrint("User-mode scanner disconnected\n");
}

// ---------------------------------------------------------------------
// Pre-write scan callback
// ---------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS
PreWriteCallback(PFLT_CALLBACK_DATA Data,
                 PCFLT_RELATED_OBJECTS FltObjects,
                 PVOID *CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);

    // --- Safety gates: skip contexts where scanning is unsafe or unwise ---

    // Paging I/O: scanning this can deadlock the system (the memory
    // manager writing out a page while waiting on a user-mode reply
    // that itself may require memory). Never scan paging writes.
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Writes originating from kernel mode (e.g. the filesystem itself,
    // or another driver) are not user-initiated file content and are
    // a common source of self-deadlock / false positives if scanned.
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Only regular file writes -- skip directories/volumes.
    if (FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->Iopb->MajorFunction != IRP_MJ_WRITE) {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    // --- Snapshot the client port under lock, don't hold the lock across
    //     FltSendMessage (which can block for up to SCAN_TIMEOUT_MS) ---
    PFLT_PORT clientPortSnapshot = NULL;
    ExAcquireFastMutex(&gClientPortLock);
    clientPortSnapshot = gClientPort;
    ExReleaseFastMutex(&gClientPortLock);

    if (clientPortSnapshot == NULL) {
        // No scanner connected. Policy choice: allow through rather than
        // block all I/O when the scanner isn't running.
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    PVOID buffer = Data->Iopb->Parameters.Write.WriteBuffer;
    ULONG length = Data->Iopb->Parameters.Write.Length;

    if (buffer == NULL || length == 0) {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    ULONG copyLength = min(length, MAX_SCAN_DATA);
    ULONG msgSize = FIELD_OFFSET(SCAN_MESSAGE, Data) + copyLength;

    PSCAN_MESSAGE msg = (PSCAN_MESSAGE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, msgSize, SCAN_POOL_TAG);

    if (msg == NULL) {
        // Allocation failure: fail open (allow) rather than crash or
        // silently corrupt state. Adjust to fail-closed if your
        // security posture requires it.
        DbgPrint("SCAN_MESSAGE allocation failed, allowing write\n");
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    // The write buffer may be a user-mode address; reading it directly
    // can fault if it's invalid/unmapped. Guard the copy.
    BOOLEAN copyOk = TRUE;
    __try {
        ProbeForRead(buffer, copyLength, sizeof(UCHAR));
        RtlCopyMemory(msg->Data, buffer, copyLength);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        copyOk = FALSE;
        DbgPrint("Exception 0x%x reading write buffer, allowing write\n",
                 GetExceptionCode());
    }

    if (!copyOk) {
        ExFreePoolWithTag(msg, SCAN_POOL_TAG);
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    // Length reflects what was ACTUALLY copied, not the raw write size --
    // UserApp.cpp trusts this field for its memmem() bounds.
    msg->Length = copyLength;

    SCAN_REPLY reply = { 0 };
    ULONG replyLen = sizeof(reply);

    LARGE_INTEGER timeout;
    timeout.QuadPart = -1LL * SCAN_TIMEOUT_MS * 10000LL; // relative, 100ns units

    NTSTATUS status = FltSendMessage(
        gFilterHandle,
        &clientPortSnapshot,
        msg,
        msgSize,
        &reply,
        &replyLen,
        &timeout
    );

    ExFreePoolWithTag(msg, SCAN_POOL_TAG);

    if (status == STATUS_TIMEOUT) {
        DbgPrint("Scan timed out after %d ms\n", SCAN_TIMEOUT_MS);
        if (!FAIL_OPEN_ON_TIMEOUT) {
            Data->IoStatus.Status = STATUS_IO_TIMEOUT;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    if (NT_SUCCESS(status)) {
        if (!reply.Allow) {
            DbgPrint("Blocking write operation\n");
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        // Allowed -- fall through.
    } else {
        // Port error (e.g. client disconnected mid-call). Fail open;
        // DisconnectNotify will have already cleared gClientPort.
        DbgPrint("FltSendMessage failed: 0x%x, allowing write\n", status);
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

// ---------------------------------------------------------------------
// Filter unload -- required for the driver to be unloadable at all
// ---------------------------------------------------------------------
NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);

    if (gServerPort) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }

    ExAcquireFastMutex(&gClientPortLock);
    if (gClientPort) {
        FltCloseClientPort(gFilterHandle, &gClientPort);
        gClientPort = NULL;
    }
    ExReleaseFastMutex(&gClientPortLock);

    if (gFilterHandle) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }

    return STATUS_SUCCESS;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_WRITE, 0, PreWriteCallback, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    FilterUnload,   // was NULL -- driver was previously unloadable
    NULL, NULL, NULL,
    NULL, NULL, NULL
};

// ---------------------------------------------------------------------
// DriverEntry
// ---------------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    ExInitializeFastMutex(&gClientPortLock);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UNICODE_STRING portName;
    RtlInitUnicodeString(&portName, L"\\MyFilterPort");

    // Restrict the communication port to admins/SYSTEM instead of the
    // default DACL, so an arbitrary unprivileged process can't connect
    // and either occupy the single connection slot or impersonate the
    // scanner and rubber-stamp every write as allowed.
    PSECURITY_DESCRIPTOR sd = NULL;
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &portName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, sd);

    status = FltCreateCommunicationPort(
        gFilterHandle,
        &gServerPort,
        &oa,
        NULL,
        ConnectNotify,
        DisconnectNotify,
        NULL,
        1
    );

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }

    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }

    return status;
}
