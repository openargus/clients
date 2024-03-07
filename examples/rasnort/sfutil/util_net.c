#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <stdio.h>

#ifndef WIN32
/* for inet_ntoa */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* WIN32 */

#include <string.h>

#include "util_net.h"

/** 
 * give a textual representation of tcp flags
 * 
 * @param flags tcph->flags
 * 
 * @return ptr to a static buffer w/ the string represented
 */
char * mktcpflag_str(int flags)
{
    static char buf[9];    
    const int fin      = 0x01;
    const int syn      = 0x02;
    const int rst      = 0x04;
    const int psh      = 0x08;
    const int ack      = 0x10;
    const int urg      = 0x20;
    const int cwr      = 0x40;
    const int ecn_echo = 0x80;
    
    memset(buf, '-', 9);
    
    if(flags & fin)
        buf[0] = 'F';

    if(flags & syn)
        buf[1] = 'S';
    
    if(flags & rst)
        buf[2] = 'R';

    if(flags & psh)
        buf[3] = 'P';

    if(flags & ack)
        buf[4] = 'A';

    if(flags & urg)
        buf[5] = 'U';
    
    if(flags & cwr)
        buf[6] = 'C';

    if(flags & ecn_echo)
        buf[7] = 'E';

    buf[8] = '\0';

    return buf;
}

/** 
 * A inet_ntoa that has 2 static buffers that are changed between
 * subsequent calls
 * 
 * @param ip ip in NETWORK BYTE ORDER
 */
char *inet_ntoax(u_int32_t ip)
{
    static char s_buf1[16];
    static char s_buf2[16];
    static int which = 0;
    char *buf;
    char *net_str;

    net_str = inet_ntoa(*(struct in_addr *)&ip);

    if(which)
    {
        buf = s_buf2;
        which = 0;
    }
    else
    {
        buf = s_buf1;
        which = 1;
    }

    snprintf(buf, 16, "%s", net_str);

    return buf;    
}


#ifdef TEST_UTIL_NET
int main(void)
{
    u_int32_t ip1 = htonl(0xFF00FF00);
    u_int32_t ip2 = htonl(0xFFAAFFAA);
        
    printf("%s -> %s\n", inet_ntoax(ip1), inet_ntoax(ip2));

    /* the following one is invalid and will break the first one*/
    printf("%s -> %s -> %s\n", inet_ntoax(ip1), inet_ntoax(ip2), inet_ntoax(ip2));
    return 0;
}
#endif /* TEST_UTIL_NET */
