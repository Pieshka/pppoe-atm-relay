#ifndef PPPOE_ATM_RELAY_H
#define PPPOE_ATM_RELAY_H

/* Basic definitions */
#define PPPOE_ATM_RELAY_VERSION "0.0.1"
#define DEFAULT_ETH_IF "eth0"
#ifndef AC_NAME
#define AC_NAME "pppoe-atm-relay"
#endif
#define PID_FILE "/var/run/pppoe_atm_relay.pid"
#define BUFFER_SIZE 2048
#define MAX_SESSIONS 4096

struct Interface
{
    char* name;
    uint8_t address[ETH_ALEN];
    uint16_t mtu;
};

struct Session
{
    pid_t pid;
    uint16_t sessionId;
    uint8_t peerMac[ETH_ALEN];
};

/* PPPoE definitions - some are already in if_pppox.h */
#define PPPOE_MIN_MTU 1492 /* Lowest acceptable MTU per RFC4638: MIN_MTU + PPP_HDR (2) + PPPOE_HDR (6) = 1500 */
#define PPPOE_OVERHEAD (PPPOE_HDR_LEN + PPP_HDR_LEN)
#define PPPOE_HDR_LEN 6
#define PPP_HDR_LEN 2
#define PPPOE_TAG_HDR_LEN 4
#define TOTAL_HDR_SIZE (ETHER_HDR_LEN + PPPOE_HDR_LEN)
#define DISCOVERY_STAGE 0x8863
#define SESSION_STAGE 0x8864
#define PPPOE_TYPE 0x1
#define PPPOE_VER 0x1

#define PTT_MAX_PAYLOAD		__cpu_to_be16(0x0120)

/* Global resources */
volatile sig_atomic_t running = 1;
int discoverySocket = -1;

/* Used by children */
int pppoaSocket = -1, pppoeSocket = -1;
int pppoaChannel = -1, pppoeChannel = -1;
int pppDevice = -1;

/* I'm quite angry. I thought - let's use children PIDs as session ids but nah
 * Session ID field has 16 bits and PIDs are much larger. So unfortunately - PID map.
 */
static int sessionCount = 0;
struct Session sessions[MAX_SESSIONS];

#endif //PPPOE_ATM_RELAY_H
