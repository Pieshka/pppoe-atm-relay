// SPDX-License-Identifier: MIT
/* pppoe-atm-relay.c - Relay between PPPoA and PPPoE */

/* Copyright 2025 by Pieszka */
/* Inspired by rp-pppoe/pppoe-server.c; 2000-2012 Roaring Penguin Software Inc.; 2018-2023 Dianne Skoll */
/* and by pppd/pppoatm.c; 2000 Mitchell Blank Jr. */

/*
 * This software enables transparent relaying of PPP packets
 * between Ethernet and Asynchronous Transfer Mode interfaces.
 *
 * On the Ethernet interface side, it acts as a PPPoE server that
 * establishes sessions and then bridges them to the ATM interface
 * using the functionality of ppp_generic.c.
 *
 * The selection of the interface, VPI, VCI and encapsulation type
 * by the client is done using the Service-Name tag, which has a
 * strictly defined structure:
 *
 * <ATM Interface>.<VPI>.<VCI>,<Encapsulation>
 * Where <Encapsulation>: 0 - auto-detection, 1 - VC-MUX, 2 - LLC
 *
 * For example, ‘0.0.35,2’ means ATM interface no. 0, VPI: 0, VCI: 35
 * and LLC encapsulation.
 *
 * Many clients can use the relay, but only one can use a specific
 * interface-VPI-VCI combination at a given time.
 *
 * The software is designed for devices such as modems and home
 * routers – effectively one ‘client’. But it supports multiple
 * clients, because why not?
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/random.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <syslog.h>
#include <signal.h>
#include <sys/wait.h>

#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <time.h>

#include <linux/if_pppox.h>
#include <linux/if_ppp.h>

#include <linux/atm.h>
#include <linux/atmdev.h>
#include <linux/atmppp.h>

#include "pppoe-atm-relay.h"

/*!
 * Clean every open resource
 */
void cleanup()
{
    syslog(LOG_INFO, "Cleaning all resources...");

    /* Close our discovery socket */
    if (discoverySocket >= 0)
    {
        close(discoverySocket);
        discoverySocket = -1;
        syslog(LOG_INFO, "Discovery socket closed");
    }

    /* Terminate all children */
    for (int i = 0; i < sessionCount; i++)
        if (sessions[i].pid > 0)
            kill(sessions[i].pid, SIGTERM);

    /* Wait for the children to exit */
    for (int i = 0; i < sessionCount; i++)
        if (sessions[i].pid > 0)
        {
            int status;
            waitpid(sessions[i].pid, &status, 0);
        }

    /* Delete PID file */
    unlink(PID_FILE);

    syslog(LOG_INFO, "Program finished operation");
    closelog();
}

/*!
 * Handle various signals
 * @param sig Signal identification
 */
void signalHandler(int sig)
{
    switch (sig)
    {
        case SIGINT:
        case SIGTERM:
            running = 0;
        default:
            break;
    }
}

/*!
 * Clean every open resource on child
 */
void cleanupChild()
{
    /* Close our discovery socket */
    if (discoverySocket >= 0)
    {
        close(discoverySocket);
        discoverySocket = -1;
        syslog(LOG_INFO, "Discovery socket closed");
    }
    /* Close our PPP device */
    if (pppDevice >= 0)
    {
        close(pppDevice);
        pppDevice = -1;
        syslog(LOG_INFO, "PPP device closed");
    }

    /* Close our atm socket */
    if (pppoaSocket >= 0)
    {
        close(pppoaSocket);
        pppoaSocket = -1;
        syslog(LOG_INFO, "ATM socket closed");
    }

    /* Close our PPPoE session socket */
    if (pppoeSocket >= 0)
    {
        close(pppoeSocket);
        pppoeSocket = -1;
        syslog(LOG_INFO, "PPPoE session socket closed");
    }

    closelog();
}

/*!
 * Write PID file
 */
void writePidFile()
{
    FILE *fp = fopen(PID_FILE, "w");
    if (fp)
    {
        fprintf(fp, "%d\n", getpid());
        fclose(fp);
    }
    else
        syslog(LOG_ERR, "Cannot write PID file: %s", strerror(errno));
}

/*!
 * Open Ethernet raw socket for PPPoE Discovery frames
 * @param interface Ethernet interface to listen on
 * @return Socket file descriptor
 */
int openDiscoverySocket(const char* interface)
{
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_ll sa;

    /* Open raw socket */
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(DISCOVERY_STAGE));
    if (sockfd < 0)
    {
        syslog(LOG_ERR, "Unable to open discovery socket on interface: %s", interface);
        fprintf(stderr, "Unable to open discovery socket on interface: %s\n", interface);
        return -1;
    }

    /* Get interface index and interface MAC address */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
    {
        syslog(LOG_ERR, "Unable to get interface %s index", interface);
        fprintf(stderr, "Unable to get interface %s index", interface);
        close(sockfd);
        return -1;
    }

    /* Bind socket to the interface */
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(DISCOVERY_STAGE);
    sa.sll_ifindex = ifr.ifr_ifindex;
    if (bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        syslog(LOG_ERR, "Unable to bind to interface %s", interface);
        fprintf(stderr, "Unable to bind to interface %s", interface);
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/*!
 * Daemonize the program -- UNIX Network Programming, Vol. 1, Stevens
 *
 */
void daemonizeProcess()
{
    pid_t pid = fork();

    /* Fork failed */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Parent leaves the scene */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* Set new session */
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    /* Ignore terminal signals */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* Do fork to prevent acquiring controlling terminal */
    pid = fork();
    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* Chroot working directory */
    if (chdir("/") != 0)
    {
        perror("chdir");
        exit(EXIT_FAILURE);
    }

    /* Close standard descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    /* Redirect them to /dev/null */
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_RDWR);

    /* Bring back SIGCHLD */
    signal(SIGCHLD, SIG_DFL);
}

/*!
 * Check if specified VPI.VCI on If is free
 * @param atmIf ATM interface
 * @param atmVpi Virtual Path Identifier
 * @param atmVci Virtual Channel Identifier
 * @return 1 if is free, 0 otherwise
 */
int checkAtmInterface(uint16_t atmIf, uint16_t atmVpi, uint16_t atmVci)
{
    int fd = socket(AF_ATMPVC, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        /* This shouldn't fail */
        syslog(LOG_ERR, "Unable to open ATM socket: %s", strerror(errno));
        return 0;
    }

    struct sockaddr_atmpvc addr = {
        .sap_family = AF_ATMPVC,
        .sap_addr.itf = atmIf,
        .sap_addr.vpi = atmVpi,
        .sap_addr.vci = atmVci
    };

    struct atm_qos qos;
    memset(&qos, 0, sizeof(qos));
    qos.txtp.traffic_class = qos.rxtp.traffic_class = ATM_UBR;
    qos.aal = ATM_AAL5;
    if (setsockopt(fd, SOL_ATM, SO_ATMQOS, &qos , sizeof(qos)) < 0)
    {
        /* We shouldn't be here */
        syslog(LOG_ERR, "Unable to set ATM socket parameters: %s", strerror(errno));
        close(fd);
        return 0;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        if (errno == EADDRINUSE)
        {
            close(fd);
            return 0;
        }
        /* We shouldn't be here */
        syslog(LOG_ERR, "Unable to bind to ATM socket not of EADDRINUSE error: %s", strerror(errno));
        close(fd);
        return 0;
    }

    close(fd);
    return 1;
}

/*!
 * Open PPP over AAL5 socket
 * @param atmIf ATM interface
 * @param atmVpi Virtual Path Identifier
 * @param atmVci Virtual Channel Identifier
 * @param encap PPPoA encapsulation type: 0 - autodetect, 1 - VC-MUX, 2 - LLC
 * @param maxSDU Maximum SDU size (without PPPoA overhead)
 * @return PPP over AAL5 file descriptor or -1 if failed
 */
int openPPPoASocket(uint8_t atmIf, uint8_t atmVpi, uint16_t atmVci, uint8_t encap, uint16_t maxSDU)
{
    int fd;
    struct atm_qos qos;
    struct atm_backend_ppp be;
    struct sockaddr_atmpvc addr = {
        .sap_family = AF_ATMPVC,
        .sap_addr.itf = atmIf,
        .sap_addr.vpi = atmVpi,
        .sap_addr.vci = atmVci
    };

    /* Open ATM PVC socket */
    fd = socket(AF_ATMPVC, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        syslog(LOG_ERR, "Unable to open ATM socket: %s", strerror(errno));
        return -1;
    }

    /* Set QoS options */
    memset(&qos, 0, sizeof(qos));
    qos.txtp.traffic_class = qos.rxtp.traffic_class = ATM_UBR;
    qos.txtp.max_sdu = qos.rxtp.max_sdu = maxSDU + (encap == PPPOATM_ENCAPS_LLC ? 6 : 2);
    qos.aal = ATM_AAL5;

    if (setsockopt(fd, SOL_ATM, SO_ATMQOS, &qos, sizeof(qos)) < 0)
    {
        syslog(LOG_ERR, "Unable to set ATM socket parameters: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Connect with our PVC address */
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        syslog(LOG_ERR, "Unable to connect with ATM PVC: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Set RAW backend */
    be.backend_num = ATM_BACKEND_PPP;
    switch (encap)
    {
        case PPPOATM_ENCAPS_LLC:
            be.encaps = PPPOATM_ENCAPS_LLC;
            break;
        case PPPOATM_ENCAPS_VC:
            be.encaps = PPPOATM_ENCAPS_VC;
            break;
        default:
            be.encaps = PPPOATM_ENCAPS_AUTODETECT;
            break;
    }

    if (ioctl(fd, ATM_SETBACKEND, &be) < 0)
    {
        syslog(LOG_ERR, "Unable to set ATM socket parameters: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

/*!
 * Open kernel-backed PPPOX session socket
 * @param sessionId PPPoE session ID in host order
 * @param macAddress Client MAC address
 * @param interface Ethernet interface to listen on
 * @return PPPOX socket file descriptor or -1 if failed
 */
int openPPPoESessionSocket(uint16_t sessionId, const uint8_t* macAddress, struct Interface interface)
{
    int fd;
    struct sockaddr_pppox sa;

    /* Open PPPoE socket */
    fd = socket(PF_PPPOX, SOCK_STREAM, PX_PROTO_OE);
    if (fd < 0)
    {
        syslog(LOG_ERR, "Unable to open PPPoX socket : %s", strerror(errno));
        return -1;
    }

    /* Prepare sockaddr */
    memset(&sa, 0, sizeof(sa));
    sa.sa_family = AF_PPPOX;
    sa.sa_protocol = PX_PROTO_OE;
    sa.sa_addr.pppoe.sid = htons(sessionId);
    memcpy(sa.sa_addr.pppoe.dev, interface.name, IFNAMSIZ);
    memcpy(sa.sa_addr.pppoe.remote, macAddress, ETH_ALEN);

    /* Connect the socket with session */
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        syslog(LOG_ERR, "Unable to connect PPPoX socket : %s", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

/*!
 * Get the specified tag from valid PPPoE packet
 * @param packet  PPPoE packet /w Ethernet header
 * @param type Tag type we are searching for
 * @return Return pointer to the tag or NULL if not found
 */
struct pppoe_tag* getTagValue(uint8_t* packet, uint16_t type)
{
    struct pppoe_hdr* pppoe = (struct pppoe_hdr *)(packet + ETHER_HDR_LEN);
    uint16_t payloadLength = ntohs(pppoe->length);
    uint8_t* tagPtr = (uint8_t*)(pppoe + 1);
    uint8_t* packetEnd = packet + ETHER_HDR_LEN + + sizeof(struct pppoe_hdr) + payloadLength;
    struct pppoe_tag* tag;
    uint16_t tagType, tagLength;

    /* Parse tags in the loop */
    while (tagPtr + sizeof(struct pppoe_hdr) <= packetEnd)
    {
        tag = (struct pppoe_tag *)tagPtr;
        tagType = tag->tag_type;
        tagLength = ntohs(tag->tag_len);

        /* Check if the length is correct */
        if (tagPtr + sizeof(struct pppoe_tag) + tagLength > packetEnd)
        {
            syslog(LOG_ERR, "Invalid tag length");
            return NULL;
        }

        /* Continue of this is not the tag we are searching for */
        if (tagType == type)
            return tag;

        tagPtr += sizeof(struct pppoe_tag) + tagLength;
    }

    return NULL;
}

void sendErrorPADS(struct Interface interface, uint8_t* packet, int errorTag, const char* error)
{
    struct ether_header* eth = (struct ether_header *)packet;
    uint8_t padsBuffer[BUFFER_SIZE];
    struct pppoe_tag *hostUniq, *relayId;
    struct ether_header* padsEthHeader = (struct ether_header *)padsBuffer;
    struct pppoe_hdr* padsPPPoEHeader = (struct pppoe_hdr *)(padsBuffer + ETHER_HDR_LEN);
    struct pppoe_tag* padsTag;
    uint8_t* padsTagPtr = padsBuffer + TOTAL_HDR_SIZE;
    size_t padsPayloadLen = 0, padsTotalLen;

    /* First the ethernet and pppoe header */
    memcpy(padsEthHeader->ether_dhost, eth->ether_shost, ETH_ALEN);
    memcpy(padsEthHeader->ether_shost, interface.address, ETH_ALEN);
    padsEthHeader->ether_type = htons(DISCOVERY_STAGE);
    padsPPPoEHeader->ver = PPPOE_VER;
    padsPPPoEHeader->type = PPPOE_TYPE;
    padsPPPoEHeader->code = PADS_CODE;
    padsPPPoEHeader->sid = 0;

    /* Error tag */
    padsTag = (struct pppoe_tag *)padsTagPtr;
    padsTag->tag_type = errorTag;
    padsTag->tag_len = htons(strlen(error));
    memcpy(padsTag->tag_data, error, ntohs(padsTag->tag_len));
    padsPayloadLen += PPPOE_TAG_HDR_LEN + ntohs(padsTag->tag_len);
    padsTagPtr += PPPOE_TAG_HDR_LEN + ntohs(padsTag->tag_len);

    /* Host-Uniq tag if exist */
    hostUniq = getTagValue(packet, PTT_HOST_UNIQ);
    if (hostUniq != NULL)
    {
        padsTag = (struct pppoe_tag *)padsTagPtr;
        padsTag->tag_type = PTT_HOST_UNIQ;
        padsTag->tag_len = hostUniq->tag_len;
        memcpy(padsTag->tag_data, hostUniq->tag_data, ntohs(padsTag->tag_len));
        padsPayloadLen += PPPOE_TAG_HDR_LEN + ntohs(padsTag->tag_len);
        padsTagPtr += PPPOE_TAG_HDR_LEN + ntohs(padsTag->tag_len);
    }

    /* Relay-Id tag if exist */
    relayId = getTagValue(packet, PTT_RELAY_SID);
    if (relayId != NULL)
    {
        padsTag = (struct pppoe_tag *)padsTagPtr;
        padsTag->tag_type = PTT_RELAY_SID;
        padsTag->tag_len = relayId->tag_len;
        memcpy(padsTag->tag_data, relayId->tag_data, ntohs(padsTag->tag_len));
        padsPayloadLen += PPPOE_TAG_HDR_LEN + ntohs(padsTag->tag_len);
        padsTagPtr += PPPOE_TAG_HDR_LEN + ntohs(padsTag->tag_len);
    }

    /* Finish the packet */
    padsPPPoEHeader->length = htons(padsPayloadLen);
    padsTotalLen = TOTAL_HDR_SIZE + padsPayloadLen;

    /* And send it */
    if (send(discoverySocket, padsBuffer, padsTotalLen, 0) < 0 && errno != ENOBUFS)
        syslog(LOG_ERR, "send() failed: %s", strerror(errno));
}

void sendPADT(struct Interface interface, const uint8_t* dstMacAddress, uint16_t sessionId)
{
    uint8_t padtBuffer[BUFFER_SIZE];
    struct ether_header* padtEthHeader = (struct ether_header *)padtBuffer;
    struct pppoe_hdr* padtPPPoEHeader = (struct pppoe_hdr *)(padtBuffer + ETHER_HDR_LEN);
    size_t padtTotalLen;

    /* First the ethernet and pppoe header */
    memcpy(padtEthHeader->ether_dhost, dstMacAddress, ETH_ALEN);
    memcpy(padtEthHeader->ether_shost, interface.address, ETH_ALEN);
    padtEthHeader->ether_type = htons(DISCOVERY_STAGE);
    padtPPPoEHeader->ver = PPPOE_VER;
    padtPPPoEHeader->type = PPPOE_TYPE;
    padtPPPoEHeader->code = PADT_CODE;
    padtPPPoEHeader->sid = htons(sessionId);
    padtPPPoEHeader->length = 0;
    padtTotalLen = TOTAL_HDR_SIZE;

    /* And send it */
    if (send(discoverySocket, padtBuffer, padtTotalLen, 0) < 0 && errno != ENOBUFS)
        syslog(LOG_ERR, "send() failed: %s", strerror(errno));
}

/*!
 * Process PADI type packet
 * @param interface Ethernet interface
 * @param packet Valid PPPoE packet
 * @param len packet length
 */
void processPADI(struct Interface interface, uint8_t* packet, size_t len)
{
    struct ether_header* eth = (struct ether_header *)packet;
    struct pppoe_tag* serviceName, *hostUniq, *relayId, *maxPayload;
    uint16_t atmIf, atmVpi, atmVci, atmEncap;
    uint16_t requestedPayload;
    int ret;

    uint8_t padoBuffer[BUFFER_SIZE];
    struct ether_header* padoEthHeader = (struct ether_header *)padoBuffer;
    struct pppoe_hdr* padoPPPoEHeader = (struct pppoe_hdr *)(padoBuffer + ETHER_HDR_LEN);
    struct pppoe_tag* padoTag;
    uint8_t* padoTagPtr = padoBuffer + TOTAL_HDR_SIZE;
    size_t padoPayloadLen = 0, padoTotalLen;

    /* Check if PADI came from a non-unicast address */
    if ((eth->ether_shost[0] & 0x01) != 0)
    {
        syslog(LOG_ERR, "Received PADI packet from non-unicast source address");
        return;
    }

    /* Get the service name */
    serviceName = getTagValue(packet, PTT_SRV_NAME);
    if (serviceName == NULL)
        /* No service name means no service */
        return;

    /* Extract some juicy data from the service name */
    ret = sscanf(serviceName->tag_data, "%hu.%hu.%hu,%hd", &atmIf, &atmVpi, &atmVci, &atmEncap);
    if (ret < 4)
    {
        /* Invalid service name also means no service */
        return;
    }

    /* Check if requested interface is free */
    if (!checkAtmInterface(atmIf, atmVpi, atmVci))
    {
        syslog(LOG_ERR, "Requested ATM %hu.%hu.%hu,%hd is already in use", atmIf, atmVpi, atmVci, atmEncap);
        return;
    }

    /* Check if we still got space for more sessions */
    if (sessionCount >= MAX_SESSIONS)
    {
        syslog(LOG_ERR, "Too many sessions established");
        return;
    }

    /* Ok, we are good to go. Let's construct a PADO packet
     * We need to send back Service Name, Relay ID and Host Uniq if they exist
     */

    /* First the ethernet and pppoe header */
    memcpy(padoEthHeader->ether_dhost, eth->ether_shost, ETH_ALEN);
    memcpy(padoEthHeader->ether_shost, interface.address, ETH_ALEN);
    padoEthHeader->ether_type = htons(DISCOVERY_STAGE);
    padoPPPoEHeader->ver = PPPOE_VER;
    padoPPPoEHeader->type = PPPOE_TYPE;
    padoPPPoEHeader->code = PADO_CODE;
    padoPPPoEHeader->sid = 0;

    /* Now the tags... */

    /* Service-Name tag */
    padoTag = (struct pppoe_tag *)padoTagPtr;
    padoTag->tag_type = PTT_SRV_NAME;
    padoTag->tag_len = serviceName->tag_len;
    memcpy(padoTag->tag_data, serviceName->tag_data, ntohs(padoTag->tag_len));
    padoPayloadLen += PPPOE_TAG_HDR_LEN + ntohs(padoTag->tag_len);
    padoTagPtr += PPPOE_TAG_HDR_LEN + ntohs(padoTag->tag_len);

    /* AC-Name tag */
    padoTag = (struct pppoe_tag *)padoTagPtr;
    padoTag->tag_type = PTT_AC_NAME;
    padoTag->tag_len = htons(strlen(AC_NAME));
    memcpy(padoTag->tag_data, AC_NAME, ntohs(padoTag->tag_len));
    padoPayloadLen += PPPOE_TAG_HDR_LEN + ntohs(padoTag->tag_len);
    padoTagPtr += PPPOE_TAG_HDR_LEN + ntohs(padoTag->tag_len);

    /* PPP-Max-Payload if exist */
    maxPayload = getTagValue(packet, PTT_MAX_PAYLOAD);
    if (maxPayload != NULL)
    {
        padoTag = (struct pppoe_tag *)padoTagPtr;
        padoTag->tag_type = PTT_MAX_PAYLOAD;
        padoTag->tag_len = maxPayload->tag_len;
        memcpy(&requestedPayload, maxPayload->tag_data, sizeof(uint16_t));
        requestedPayload = ntohs(requestedPayload);

        /* As per RFC4638 let's check for MTU boundness */
        if (requestedPayload < PPPOE_MIN_MTU)
            requestedPayload = PPPOE_MIN_MTU;
        else if (requestedPayload > (interface.mtu - PPPOE_OVERHEAD))
            requestedPayload = interface.mtu - PPPOE_OVERHEAD;

        /* RFC doesn't specify if we should ignore the tag when is incorrect or not.
         * So we'll include it anyway
         */
        requestedPayload = htons(requestedPayload);
        memcpy(padoTag->tag_data, &requestedPayload, ntohs(padoTag->tag_len));
        padoPayloadLen += PPPOE_TAG_HDR_LEN + ntohs(padoTag->tag_len);
        padoTagPtr += PPPOE_TAG_HDR_LEN + ntohs(padoTag->tag_len);
    }

    /* Host-Uniq tag if exist */
    hostUniq = getTagValue(packet, PTT_HOST_UNIQ);
    if (hostUniq != NULL)
    {
        padoTag = (struct pppoe_tag *)padoTagPtr;
        padoTag->tag_type = PTT_HOST_UNIQ;
        padoTag->tag_len = hostUniq->tag_len;
        memcpy(padoTag->tag_data, hostUniq->tag_data, ntohs(padoTag->tag_len));
        padoPayloadLen += PPPOE_TAG_HDR_LEN + ntohs(padoTag->tag_len);
        padoTagPtr += PPPOE_TAG_HDR_LEN + ntohs(padoTag->tag_len);
    }

    /* Relay-Id tag if exist */
    relayId = getTagValue(packet, PTT_RELAY_SID);
    if (relayId != NULL)
    {
        padoTag = (struct pppoe_tag *)padoTagPtr;
        padoTag->tag_type = PTT_RELAY_SID;
        padoTag->tag_len = relayId->tag_len;
        memcpy(padoTag->tag_data, relayId->tag_data, ntohs(padoTag->tag_len));
        padoPayloadLen += PPPOE_TAG_HDR_LEN + ntohs(padoTag->tag_len);
        padoTagPtr += PPPOE_TAG_HDR_LEN + ntohs(padoTag->tag_len);
    }

    /* Finish the packet */
    padoPPPoEHeader->length = htons(padoPayloadLen);
    padoTotalLen = TOTAL_HDR_SIZE + padoPayloadLen;

    /* And send it */
    if (send(discoverySocket, padoBuffer, padoTotalLen, 0) < 0 && errno != ENOBUFS)
        syslog(LOG_ERR, "send() failed: %s", strerror(errno));
}

/*!
 * Process PADR type packet
 * @param interface Ethernet interface
 * @param packet Valid PPPoE packet
 * @param len packet length
 */
void processPADR(struct Interface interface, uint8_t* packet, size_t len)
{
    struct ether_header* eth = (struct ether_header *)packet;
    struct pppoe_tag* serviceName, *hostUniq, *relayId, *maxPayload;
    uint8_t atmIf, atmVpi, atmEncap;
    uint16_t atmVci;
    int ret;
    pid_t childPid;
    uint16_t sessionId, requestedPayload = PPPOE_MIN_MTU;

    /* Check if PADR is not directed to us */
    if (memcmp(eth->ether_dhost, interface.address, ETH_ALEN) !=0)
        return;

    /* Check if PADR came from a non-unicast address */
    if ((eth->ether_shost[0] & 0x01) != 0)
    {
        syslog(LOG_ERR, "Received PADR packet from non-unicast source address");
        return;
    }

    /* Get the service name */
    serviceName = getTagValue(packet, PTT_SRV_NAME);
    if (serviceName == NULL)
    {
        syslog(LOG_ERR, "Received PADR packet without service name tag");
        sendErrorPADS(interface, packet, PTT_SRV_ERR, "No service name tag");
        return;
    }

    /* Extract some juicy data from the service name */
    ret = sscanf(serviceName->tag_data, "%hhu.%hhu.%hu,%hhu", &atmIf, &atmVpi, &atmVci, &atmEncap);
    if (ret < 4)
    {
        syslog(LOG_ERR, "Received PADR packet with invalid service name tag");
        sendErrorPADS(interface, packet, PTT_SRV_ERR, "Invalid service name tag");
        return;
    }

    /* Check if requested interface is still free */
    if (!checkAtmInterface(atmIf, atmVpi, atmVci))
    {
        syslog(LOG_ERR, "Requested ATM %hhu.%hhu.%hu,%hhu is already in use", atmIf, atmVpi, atmVci, atmEncap);
        sendErrorPADS(interface, packet, PTT_SRV_ERR, "Requested ATM PVC is already in use");
        return;
    }

    /* Check if we still got space for more sessions */
    if (sessionCount >= MAX_SESSIONS)
    {
        syslog(LOG_ERR, "Too many sessions established");
        sendErrorPADS(interface, packet, PTT_SRV_ERR, "Too many sessions established");
        return;
    }

    /* Generate session ID before everything */
    if (getrandom(&sessionId, sizeof(sessionId), 0) <= 0)
    {
        syslog(LOG_ERR, "Cannot generate random session ID");
        sendErrorPADS(interface, packet, PTT_SRV_ERR, "Cannot generate random session ID");
        return;
    }

    /* Ok, we are good to go. We'll fork ourselves and let the child handle everything
     * We need to open a PPPOE socket with our session and send back the PADS packet
     */
    childPid = fork();
    if (childPid < 0)
    {
        sendErrorPADS(interface, packet, PTT_SYS_ERR, "Failed to start session process");
        syslog(LOG_ERR, "Failed to start session process");
        return;
    }

    /* In the parent process we associate session ID with child and return */
    if (childPid > 0)
    {
        if (running == 0) return; /* Goodbye if we're not running */
        memcpy(sessions[sessionCount].peerMac, eth->ether_shost, ETH_ALEN);
        sessions[sessionCount].sessionId = sessionId;
        sessions[sessionCount++].pid = childPid;
        return;
    }

    /* Now in the child process */

    /* Change signal handlers */
    signal(SIGTERM, signalHandler);
    signal(SIGINT, signalHandler);

    /* Close all file descriptors except the discovery socket */
    closelog();
    for (int i = 0; i < sysconf(_SC_OPEN_MAX); i++)
        if (i != discoverySocket)
            close(i);

    /* Open new syslog */
    openlog("pppoe-atm-relay-child", LOG_PID, LOG_DAEMON);

    /* We need to get our maximum payload size if specified */
    maxPayload = getTagValue(packet, PTT_MAX_PAYLOAD);
    if (maxPayload != NULL)
    {
        memcpy(&requestedPayload, maxPayload->tag_data, sizeof(uint16_t));
        requestedPayload = ntohs(requestedPayload);
        /* As per RFC4638 let's check for MTU boundness */
        if (requestedPayload < PPPOE_MIN_MTU)
            requestedPayload = PPPOE_MIN_MTU;
        else if (requestedPayload > (interface.mtu - PPPOE_OVERHEAD))
            requestedPayload = interface.mtu - PPPOE_OVERHEAD;
    }


    /* Open PPPoA socket */
    pppoaSocket = openPPPoASocket(atmIf, atmVpi, atmVci, atmEncap, requestedPayload);
    if (pppoaSocket < 0)
    {
        sendErrorPADS(interface, packet, PTT_SYS_ERR, "Failed to open PPPoA socket");
        syslog(LOG_ERR, "Failed to open PPPoA socket");
        cleanupChild();
        exit(EXIT_FAILURE);
    }

    /* Open PPPOX socket */
    pppoeSocket = openPPPoESessionSocket(sessionId, eth->ether_shost, interface);
    if (pppoeSocket < 0)
    {
        sendErrorPADS(interface, packet, PTT_SYS_ERR, "Failed to open PPPoE socket");
        syslog(LOG_ERR, "Failed to open PPPoE socket");
        cleanupChild();
        exit(EXIT_FAILURE);
    }

    /* Get PPPoA channel */
    if (ioctl(pppoaSocket, PPPIOCGCHAN, &pppoaChannel) < 0)
    {
        sendErrorPADS(interface, packet, PTT_SYS_ERR, "Failed to get PPPoA channel");
        syslog(LOG_ERR, "Failed to get PPPoA channel");
        cleanupChild();
        exit(EXIT_FAILURE);
    }

    /* Get PPPoE channel */
    if (ioctl(pppoeSocket, PPPIOCGCHAN, &pppoeChannel) < 0)
    {
        sendErrorPADS(interface, packet, PTT_SYS_ERR, "Failed to get PPPoE channel");
        syslog(LOG_ERR, "Failed to get PPPoE channel");
        cleanupChild();
        exit(EXIT_FAILURE);
    }

    /* Open PPP device */
    pppDevice = open("/dev/ppp", O_RDWR);
    if ( pppDevice < 0)
    {
        sendErrorPADS(interface, packet, PTT_SYS_ERR, "Failed to open /dev/ppp");
        syslog(LOG_ERR, "Failed to open /dev/ppp");
        cleanupChild();
        exit(EXIT_FAILURE);
    }

    /* Attach PPPoE channel to device */
    if (ioctl(pppDevice, PPPIOCATTCHAN, &pppoeChannel) < 0)
    {
        sendErrorPADS(interface, packet, PTT_SYS_ERR, "Failed to attach PPPoE channel to device");
        syslog(LOG_ERR, "Failed to attach PPPoE channel to device");
        cleanupChild();
        exit(EXIT_FAILURE);
    }

    /* Bridge PPPoA<->PPPoE */
    if (ioctl(pppDevice, PPPIOCBRIDGECHAN, &pppoaChannel) < 0)
    {
        sendErrorPADS(interface, packet, PTT_SYS_ERR, "Failed to setup PPPoA<->PPPoE bridge");
        syslog(LOG_ERR, "Failed to setup PPPoA<->PPPoE bridge");
        cleanupChild();
        exit(EXIT_FAILURE);
    }

    /* We can close PPP device at the moment */
    close(pppDevice);

    /* Prepare and send back PADS packet */
    uint8_t padsBuffer[BUFFER_SIZE];
    struct ether_header* padsEthHeader = (struct ether_header *)padsBuffer;
    struct pppoe_hdr* padsPPPoEHeader = (struct pppoe_hdr *)(padsBuffer + ETHER_HDR_LEN);
    struct pppoe_tag* padsTag;
    uint8_t* padsTagPtr = padsBuffer + TOTAL_HDR_SIZE;
    size_t padsPayloadLen = 0, padsTotalLen;

    /* First the ethernet and pppoe header */
    memcpy(padsEthHeader->ether_dhost, eth->ether_shost, ETH_ALEN);
    memcpy(padsEthHeader->ether_shost, interface.address, ETH_ALEN);
    padsEthHeader->ether_type = htons(DISCOVERY_STAGE);
    padsPPPoEHeader->ver = PPPOE_VER;
    padsPPPoEHeader->type = PPPOE_TYPE;
    padsPPPoEHeader->code = PADS_CODE;
    padsPPPoEHeader->sid = htons(sessionId);

    /* Now the tags... */
    /* Service-Name tag */
    padsTag = (struct pppoe_tag *)padsTagPtr;
    padsTag->tag_type = PTT_SRV_NAME;
    padsTag->tag_len = serviceName->tag_len;
    memcpy(padsTag->tag_data, serviceName->tag_data, ntohs(padsTag->tag_len));
    padsPayloadLen += PPPOE_TAG_HDR_LEN + ntohs(padsTag->tag_len);
    padsTagPtr += PPPOE_TAG_HDR_LEN + ntohs(padsTag->tag_len);

    /* AC-Name tag */
    padsTag = (struct pppoe_tag *)padsTagPtr;
    padsTag->tag_type = PTT_AC_NAME;
    padsTag->tag_len = htons(strlen(AC_NAME));
    memcpy(padsTag->tag_data, AC_NAME, ntohs(padsTag->tag_len));
    padsPayloadLen += PPPOE_TAG_HDR_LEN + ntohs(padsTag->tag_len);
    padsTagPtr += PPPOE_TAG_HDR_LEN + ntohs(padsTag->tag_len);

    /* PPP-Max-Payload if exist */
    if (maxPayload != NULL)
    {
        padsTag = (struct pppoe_tag *)padsTagPtr;
        padsTag->tag_type = PTT_MAX_PAYLOAD;
        padsTag->tag_len = maxPayload->tag_len;

        /* We checked for everything already */
        /* RFC doesn't specify if we should ignore the tag when is incorrect or not.
         * So we'll include it anyway
         */
        requestedPayload = htons(requestedPayload);
        memcpy(padsTag->tag_data, &requestedPayload, ntohs(padsTag->tag_len));
        padsPayloadLen += PPPOE_TAG_HDR_LEN + ntohs(padsTag->tag_len);
        padsTagPtr += PPPOE_TAG_HDR_LEN + ntohs(padsTag->tag_len);
    }

    /* Host-Uniq tag if exist */
    hostUniq = getTagValue(packet, PTT_HOST_UNIQ);
    if (hostUniq != NULL)
    {
        padsTag = (struct pppoe_tag *)padsTagPtr;
        padsTag->tag_type = PTT_HOST_UNIQ;
        padsTag->tag_len = hostUniq->tag_len;
        memcpy(padsTag->tag_data, hostUniq->tag_data, ntohs(padsTag->tag_len));
        padsPayloadLen += PPPOE_TAG_HDR_LEN + ntohs(padsTag->tag_len);
        padsTagPtr += PPPOE_TAG_HDR_LEN + ntohs(padsTag->tag_len);
    }

    /* Relay-Id tag if exist */
    relayId = getTagValue(packet, PTT_RELAY_SID);
    if (relayId != NULL)
    {
        padsTag = (struct pppoe_tag *)padsTagPtr;
        padsTag->tag_type = PTT_RELAY_SID;
        padsTag->tag_len = relayId->tag_len;
        memcpy(padsTag->tag_data, relayId->tag_data, ntohs(padsTag->tag_len));
        padsPayloadLen += PPPOE_TAG_HDR_LEN + ntohs(padsTag->tag_len);
        padsTagPtr += PPPOE_TAG_HDR_LEN + ntohs(padsTag->tag_len);
    }

    /* Finish the packet */
    padsPPPoEHeader->length = htons(padsPayloadLen);
    padsTotalLen = TOTAL_HDR_SIZE + padsPayloadLen;

    /* And send it */
    if (send(discoverySocket, padsBuffer, padsTotalLen, 0) < 0 && errno != ENOBUFS)
    {
        syslog(LOG_ERR, "send() failed: %s", strerror(errno));
        cleanupChild();
        exit(EXIT_FAILURE);
    }

    /* We shouldn't be totally silent, should we? */
    syslog(LOG_INFO, "Successfully established relay connection between ATM path: %u.%u.%u and Ethernet host: "
            "%02X:%02X:%02X:%02X:%02X:%02X, under session ID: %u.",
            atmIf, atmVpi, atmVci,
            eth->ether_shost[0],
            eth->ether_shost[1],
            eth->ether_shost[2],
            eth->ether_shost[3],
            eth->ether_shost[4],
            eth->ether_shost[5],
            sessionId);

    /* Wait for some interrupt */
    /* To be honest we don't need to fork,
     * but termination sessions is much
     * easier that way.
     */
    while (running)
        pause();


    /* If we exit - send PADT, clean everything */
    sendPADT(interface, eth->ether_shost, sessionId);
    cleanupChild();
    exit(EXIT_SUCCESS);
}

/*!
 * Process PADT type packet
 * @param interface Ethernet interface
 * @param packet Valid PPPoE packet
 * @param len packet length
 */
void processPADT(struct Interface interface, uint8_t* packet, size_t len)
{
    struct ether_header* eth = (struct ether_header *)packet;
    struct pppoe_hdr* pppoe = (struct pppoe_hdr *)(packet + ETHER_HDR_LEN);
    int sessionIndex = 0;

    /* Check if PADT is not directed to us */
    if (memcmp(eth->ether_dhost, interface.address, ETH_ALEN) != 0)
        return;

    /* Check if PADT came from a non-unicast address */
    if ((eth->ether_shost[0] & 0x01) != 0)
    {
        syslog(LOG_ERR, "Received PADT packet from non-unicast source address");
        return;
    }

    /* Find our session */
    for (sessionIndex = 0; sessionIndex < MAX_SESSIONS; sessionIndex++)
        if (sessions[sessionIndex].sessionId == ntohs(pppoe->sid))
            break;

    if (sessionIndex >= MAX_SESSIONS)
    {
        syslog(LOG_WARNING, "Requested termination of session that does not exit");
        return;
    }

    /* Check if MAC address is correct */
    if (memcmp(eth->ether_shost, sessions[sessionIndex].peerMac, ETH_ALEN) != 0)
    {
        syslog(LOG_WARNING, "Termination request for session %u received from "
            "%02X:%02X:%02X:%02X:%02X:%02X, but should be from "
            "%02X:%02X:%02X:%02X:%02X:%02X",
            sessions[sessionIndex].sessionId,
            eth->ether_shost[0],
            eth->ether_shost[1],
            eth->ether_shost[2],
            eth->ether_shost[3],
            eth->ether_shost[4],
            eth->ether_shost[5],
            sessions[sessionIndex].peerMac[0],
            sessions[sessionIndex].peerMac[1],
            sessions[sessionIndex].peerMac[2],
            sessions[sessionIndex].peerMac[3],
            sessions[sessionIndex].peerMac[4],
            sessions[sessionIndex].peerMac[5]);
        return;
    }

    /* Terminate the process if it's not terminated */
    if (sessions[sessionIndex].pid > 0)
    {
        kill(sessions[sessionIndex].pid, SIGTERM);
        sessions[sessionIndex].pid = 0;
    }

    /* Rearrange the session table */
    sessions[sessionIndex] = sessions[sessionCount - 1];
    sessionCount--;
}

/*!
 * Show help
 * @param argv0 Name of the program
 */
void help(const char* argv0)
{
    fprintf(stderr, "Usage: %s [options]\n", argv0);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "\t-h: Show this help.\n");
    fprintf(stderr, "\t-v: Show version.\n");
    fprintf(stderr, "\t-i: Specify ethernet interface (default %s).\n", DEFAULT_ETH_IF);
    fprintf(stderr, "\t-f: Run in foreground.\n");
}

/*!
 * Main function of the PPPoE to ATM relay
 * @return Exit status
 */
int main(int argc, char **argv)
{
    int daemonize = 1;
    int opt;
    struct Interface intf = {
        .name = DEFAULT_ETH_IF
    };
    struct ifreq ifr;
    int ifIsSet = 0;
    uint8_t buffer[BUFFER_SIZE];

    /* Parse argumnets */
    const char* options = "hvfi:";
    while ((opt = getopt(argc, argv, options)) != -1)
    {
        switch (opt)
        {
            case 'h':
                help(argv[0]);
                exit(EXIT_SUCCESS);
            case 'v':
                fprintf(stderr, "%s\n", PPPOE_ATM_RELAY_VERSION);
                exit(EXIT_SUCCESS);
            case 'i':
                if (optarg)
                {
                    intf.name = strdup(optarg);
                    if (!intf.name)
                    {
                        fprintf(stderr, "Out of memory.\n");
                        exit(EXIT_FAILURE);
                    }
                    ifIsSet = 1;
                }
                break;
            case 'f':
                daemonize = 0;
                break;
            default:
                break;
        }
    }

    /* Open syslog log */
    openlog(argv[0], LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "PPPoE to ATM relay, version: %s, started.", PPPOE_ATM_RELAY_VERSION);

    /* Daemonize if we should */
    if (daemonize)
        daemonizeProcess();

    /* Save pid file */
    writePidFile();

    /* Register signal handlers */
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    /* Open ethernet socket */
    discoverySocket = openDiscoverySocket(intf.name);
    if (discoverySocket < 0)
    {
        cleanup();
        if (ifIsSet)
            free(intf.name);
        exit(EXIT_FAILURE);
    }

    /* Get MAC address */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, intf.name, IFNAMSIZ - 1);
    if (ioctl(discoverySocket, SIOCGIFHWADDR, &ifr) < 0)
    {
        syslog(LOG_ERR, "Can't get MAC address of the interface");
        fprintf(stderr, "Can't get MAC address of the interface");
        cleanup();
        if (ifIsSet)
            free(intf.name);
        exit(EXIT_FAILURE);
    }
    memcpy(intf.address, ifr.ifr_addr.sa_data, ETH_ALEN);

    /* Get MTU */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, intf.name, IFNAMSIZ - 1);
    if (ioctl(discoverySocket, SIOCGIFMTU, &ifr) < 0)
    {
        syslog(LOG_ERR, "Can't get MTU of the interface");
        fprintf(stderr, "Can't get MTU of the interface");
        cleanup();
        if (ifIsSet)
            free(intf.name);
        exit(EXIT_FAILURE);
    }
    intf.mtu = ifr.ifr_mtu;

    /* Main loop */
    syslog(LOG_INFO, "Program is ready to serve...");
    while (running)
    {
        fd_set readFds;
        FD_ZERO(&readFds);
        FD_SET(discoverySocket, &readFds);
        int ret;
        ssize_t len;
        struct ether_header* eth;
        struct pppoe_hdr* pppoe;

        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        /* Monitor our socket */
        ret = select(discoverySocket + 1, &readFds, NULL, NULL, &timeout);
        if (ret < 0)
        {
            syslog(LOG_ERR, "Select failed");
            cleanup();
            if (ifIsSet)
                free(intf.name);
            exit(EXIT_FAILURE);
        }
        if (ret == 0)
            continue;

        /* Receive data */
        if (FD_ISSET(discoverySocket, &readFds))
        {
            len = recvfrom(discoverySocket, buffer, BUFFER_SIZE, 0, NULL, NULL);
            if (len < 0)
            {
                syslog(LOG_ERR, "Receive failed");
                cleanup();
                exit(EXIT_FAILURE);
            }

            /* Something went wrong */
            if (len < TOTAL_HDR_SIZE)
                continue;

            /* Get information about our frame */
            eth = (struct ether_header *)buffer;
            if (ntohs(eth->ether_type) != DISCOVERY_STAGE)
                continue; /* Better safe than sorry */

            /* Get PPPoE header */
            pppoe = (struct pppoe_hdr *)(buffer + ETHER_HDR_LEN);

            /* Check if we got the right version and type */
            if (pppoe->ver != PPPOE_VER || pppoe->type != PPPOE_TYPE)
                continue;

            /* Check length */
            if (ntohs(pppoe->length) + TOTAL_HDR_SIZE > len)
            {
                syslog(LOG_ERR, "Received too large packet");
                continue;
            }

            /* Now let's process what we got */
            switch (pppoe->code)
            {
                case PADI_CODE:
                    processPADI(intf, buffer, len);
                    break;
                case PADR_CODE:
                    processPADR(intf, buffer, len);
                    break;
                case PADT_CODE:
                    processPADT(intf, buffer, len);
                    break;
                case PADO_CODE:
                case PADS_CODE:
                default:
                    /* Ignore unnecessary frames */
                    break;
            }
        }
    }

    /* Clean everything up */
    cleanup();
    if (ifIsSet)
        free(intf.name);
    return 0;
}