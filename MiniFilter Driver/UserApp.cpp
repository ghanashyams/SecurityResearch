#include <windows.h>
#include <fltUser.h>
#include <stdio.h>

HANDLE hPort = NULL;
volatile BOOL gRunning = TRUE;

typedef struct _SCAN_MESSAGE {
    ULONG Length;      // number of bytes actually present in Data (see Driver_App.cpp fix)
    UCHAR Data[1];
} SCAN_MESSAGE, *PSCAN_MESSAGE;

typedef struct _SCAN_REPLY {
    BOOLEAN Allow;
} SCAN_REPLY, *PSCAN_REPLY;

// Every reply to FilterReplyMessage must begin with FILTER_REPLY_HEADER,
// carrying back the MessageId the kernel sent us -- otherwise Filter
// Manager has no way to match the reply to the pending FltSendMessage call.
typedef struct _SCAN_REPLY_MESSAGE {
    FILTER_REPLY_HEADER ReplyHeader;
    SCAN_REPLY           Reply;
} SCAN_REPLY_MESSAGE, *PSCAN_REPLY_MESSAGE;

// MSVC's CRT does not provide memmem (it's a glibc/BSD extension) --
// minimal portable equivalent, sufficient for small needle sizes like ours.
static const void *FindBytes(const void *haystack, size_t haystackLen,
                              const void *needle, size_t needleLen) {
    if (needleLen == 0 || haystackLen < needleLen) {
        return NULL;
    }
    const UCHAR *h = (const UCHAR *)haystack;
    const UCHAR *n = (const UCHAR *)needle;
    size_t last = haystackLen - needleLen;
    for (size_t i = 0; i <= last; i++) {
        if (memcmp(h + i, n, needleLen) == 0) {
            return h + i;
        }
    }
    return NULL;
}

BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    UNREFERENCED_PARAMETER(ctrlType);
    // Signal the loop to exit and unblock FilterGetMessage by closing the
    // port -- without this, Ctrl+C / service-stop has no clean exit path
    // and the process can only be killed.
    gRunning = FALSE;
    if (hPort) {
        CloseHandle(hPort);
        hPort = NULL;
    }
    return TRUE;
}

int main() {
    HRESULT hr = FilterConnectCommunicationPort(
        L"\\MyFilterPort",
        0,
        NULL,
        0,
        NULL,
        &hPort
    );

    if (FAILED(hr)) {
        printf("Failed to connect: 0x%x\n", hr);
        return 1;
    }

    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    BYTE buffer[4096];
    int consecutiveFailures = 0;

    while (gRunning) {
        hr = FilterGetMessage(hPort, (PFILTER_MESSAGE_HEADER)buffer, sizeof(buffer), NULL);

        if (FAILED(hr)) {
            if (!gRunning) {
                break; // expected: port closed by ConsoleCtrlHandler
            }
            printf("FilterGetMessage failed: 0x%x\n", hr);
            // Avoid a tight CPU-burning loop if the port is failing
            // repeatedly (e.g. driver unloading, port torn down).
            if (++consecutiveFailures >= 5) {
                printf("Too many consecutive failures, exiting\n");
                break;
            }
            Sleep(100);
            continue;
        }
        consecutiveFailures = 0;

        PFILTER_MESSAGE_HEADER msgHeader = (PFILTER_MESSAGE_HEADER)buffer;
        PSCAN_MESSAGE msg = (PSCAN_MESSAGE)(msgHeader + 1);

        // Defense in depth: don't trust Length beyond what actually fits in
        // the buffer we received, regardless of what the driver claims.
        size_t headerAndFixedSize = sizeof(FILTER_MESSAGE_HEADER) + FIELD_OFFSET(SCAN_MESSAGE, Data);
        if (headerAndFixedSize > sizeof(buffer)) {
            printf("Malformed message: header alone exceeds buffer\n");
            continue;
        }
        size_t maxDataLen = sizeof(buffer) - headerAndFixedSize;
        ULONG effectiveLength = msg->Length;
        if (effectiveLength > maxDataLen) {
            printf("Message Length (%lu) exceeds received buffer, clamping\n", effectiveLength);
            effectiveLength = (ULONG)maxDataLen;
        }

        printf("Received %lu bytes\n", effectiveLength);

        SCAN_REPLY_MESSAGE replyMsg;
        replyMsg.ReplyHeader.Status = 0; // STATUS_SUCCESS
        replyMsg.ReplyHeader.MessageId = msgHeader->MessageId; // required for correlation
        replyMsg.Reply.Allow = TRUE;

        // Example scan: block if buffer contains "SECRET"
        static const char needle[] = "SECRET";
        if (FindBytes(msg->Data, effectiveLength, needle, sizeof(needle) - 1) != NULL) {
            printf("Sensitive content detected, blocking\n");
            replyMsg.Reply.Allow = FALSE;
        }

        // Per Microsoft guidance: use the explicit header+payload size,
        // not sizeof(SCAN_REPLY_MESSAGE) -- struct padding can make the
        // latter larger than the two parts combined, which FltSendMessage
        // on the kernel side would reject with STATUS_BUFFER_OVERFLOW.
        DWORD replySize = (DWORD)(sizeof(FILTER_REPLY_HEADER) + sizeof(SCAN_REPLY));

        hr = FilterReplyMessage(hPort, (PFILTER_REPLY_HEADER)&replyMsg, replySize);
        if (FAILED(hr)) {
            printf("Failed to reply: 0x%x\n", hr);
        }
    }

    if (hPort) {
        CloseHandle(hPort);
        hPort = NULL;
    }
    return 0;
}
