/*
 * nbee_link.cpp
 *
 *  Created on: Jul 18, 2011
 *      Author: rdenicol
 */

#include <iostream>
#include <map>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <nbee.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <signal.h>


#include "nbee_link.h"
#include "oflib/oxm-match.h"
#include "oflib/ofl-utils.h"
#include "lib/hash.h"
#include "lib/fatal-signal.h"

map<uint16_t,uint16_t> ext_hdr_orders;

nbPacketDecoder *Decoder;
nbPacketDecoderVars* PacketDecoderVars;
nbNetPDLLinkLayer_t LinkLayerType;
nbPDMLReader *PDMLReader;
int PacketCounter= 1;
struct pcap_pkthdr * pkhdr;


#define NETPDLFILE "customnetpdl.xml"


static void
sigint_handler(int sig_nr)
{

    nbDeallocatePacketDecoder(Decoder);
    nbCleanup();

    exit(0);
}

extern "C" int nblink_initialize(void)
{

    char ErrBuf[ERRBUF_SIZE + 1];
    int NetPDLProtoDBFlags = nbPROTODB_MINIMAL;
    int NetPDLDecoderFlags = nbDECODER_GENERATEPDML;
    int ShowNetworkNames = 0;

    char* NetPDLFileName = (char*) NETPDLDIR"/"NETPDLFILE;
    struct stat netpdlstat;

    struct sigaction sa;

   /* Set up signal handler. */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGINT, &sa, NULL)) {
        ofp_fatal(errno, "sigterm(SIGINT) failed");
    }

    pkhdr = new struct pcap_pkthdr;

    if (nbIsInitialized() == nbFAILURE)
    {
        if (stat(NETPDLFILE, &netpdlstat) > 0 || errno != ENOENT)
        {
                NetPDLFileName += sizeof(NETPDLDIR) + 1 - 1; /* null char and '/' cancel out */
        }

        if (nbInitialize(NetPDLFileName, NetPDLProtoDBFlags, ErrBuf, sizeof(ErrBuf)) == nbFAILURE)
        {
            printf("Error initializing the NetBee Library; %s\n", ErrBuf);
            return nbFAILURE;
        }
    }

    Decoder= nbAllocatePacketDecoder(NetPDLDecoderFlags, ErrBuf, sizeof(ErrBuf));
    if (Decoder == NULL)
    {
        printf("Error creating the NetPDLParser: %s.\n", ErrBuf);
        return nbFAILURE;
    }

    // Get the PacketDecoderVars; let's do the check, although it is not really needed
    if ((PacketDecoderVars= Decoder->GetPacketDecoderVars()) == NULL)
    {
        printf("Error: cannot get an instance of the nbPacketDecoderVars class.\n");
        return nbFAILURE;
    }
    // Set the appropriate NetPDL configuration variables
    //  PacketDecoderVars->SetVariableNumber((char*) NETPDL_VARIABLE_SHOWNETWORKNAMES, ShowNetworkNames);

    if (PacketDecoderVars->SetVariableNumber((char*) NETPDL_VARIABLE_SHOWNETWORKNAMES, ShowNetworkNames)==nbFAILURE)
    {
        printf("Error: cannot set variables of the decoder properly.\n");
        return nbFAILURE;
    }

    PDMLReader = Decoder->GetPDMLReader();

    return 0;

}

int nblink_add_entry_hmap(struct ofpbuf * pktin, struct hmap * pktout ,struct ofl_match_tlv * pktout_field, int Size)
/*
* This will add a field entry to the hash map structure.
*/
{


    return 0;
}

int nblink_check_for_entry_on_hmap(struct hmap * pktout ,uint32_t  header, struct ofl_match_tlv * field)
/*
* This search for an entry on the hmap and points field to it.
* If no entry is found, -1 is returned.
*/
{
    struct ofl_match_tlv *iter;
    bool done=0;
    HMAP_FOR_EACH(iter,struct ofl_match_tlv, hmap_node,pktout)
    {
        if(iter->header == header)
        {
            /* Adding entry to existing hash entry (for now, do this only to ethertype)*/
            field = iter;
            return 0;
        }
    }
    return -1;
}

/*
* Function used to extract an Extension Header flag from the NetBee field structure.
*/
int nblink_extract_exthdr_fields(struct ofpbuf * pktin, struct ofl_match * pktout, uint16_t type, _nbPDMLField * field, int *destination_num)
{
    struct ofl_match_tlv *iter;
    uint16_t *ext_hdrs;


    if (type == OFPIEH_DEST){
        (*destination_num)++;
    }

    HMAP_FOR_EACH_WITH_HASH(iter, struct ofl_match_tlv, hmap_node, hash_int(OXM_OF_IPV6_EXTHDR, 0), &pktout->match_fields)
    {
        /*First check if is duplicated*/
        ext_hdrs = (uint16_t*) iter->value;
        *ext_hdrs = *ext_hdrs;
        if(!(*ext_hdrs & OFPIEH_UNREP)){
            if (type != OFPIEH_DEST && *ext_hdrs & type){
                *ext_hdrs ^=  OFPIEH_UNREP;
                return 0;
            }
            /*DOH can appear twice */
            if(*ext_hdrs & type && *destination_num > 2){
                *ext_hdrs ^=  OFPIEH_UNREP;
                return 0;
            }
        }

        /*Check sequence*/
        if(!(*ext_hdrs & OFPIEH_UNSEQ)){
            uint16_t next_type;
            char *pEnd;
            uint16_t next_header = strtol(field->FirstChild->Value, &pEnd,16);
            /*Set OFPIEH_NONEXT */
            if (next_header == IPV6_NO_NEXT_HEADER)
                *ext_hdrs ^=  OFPIEH_NONEXT;

            /*DOH Should have a routing header or the upper layer as the next header
              if not, set the UNSEQ bit                                            */
            if(type == OFPIEH_DEST){
                if ( next_header == IPV6_TYPE_HBH
                    || next_header == IPV6_TYPE_FH || next_header == IPV6_TYPE_AH ||
                    next_header == IPV6_TYPE_ESP ){
                    *ext_hdrs ^=  OFPIEH_DEST;
                    *ext_hdrs ^=  OFPIEH_UNSEQ;
                    *ext_hdrs = htons(*ext_hdrs);
                    return 0;
                }
            }
            map<uint16_t,uint16_t>::iterator it;
            it = ext_hdr_orders.find(type);
            if(next_header == IPV6_TYPE_HBH)
                next_type = HBH;
            else if(next_header == IPV6_TYPE_DOH){
                next_type = DESTINATION;
            }
            else if (next_header == IPV6_TYPE_RH)
                next_type = ROUTING;
            else if (next_header == IPV6_TYPE_FH)
                next_type = FRAGMENT;
            else if (next_header == IPV6_TYPE_AH)
                next_type = AUTHENTICATION;
            else if (next_header == IPV6_TYPE_ESP)
                next_type = ESP;
            else next_type = 0xffff;
            if(!(it->second & next_type))
                /*Set the not in order preferred bit */
                *ext_hdrs ^=  OFPIEH_UNSEQ;
        }

        /* Set the extension header flag*/
        *ext_hdrs ^=  type;
        *ext_hdrs = *ext_hdrs;
    }

    return 0;
}


int nblink_extract_proto_fields(struct ofpbuf * pktin, _nbPDMLField * field, struct ofl_match * pktout, uint32_t header)
/*
* Function used to extract a field from the NetBee field structure.
*/
{
/* Found a NetPDL field usable on matching */

    /* Copying data from the packet */
    if (field->Mask != NULL)
    {
        uint8_t i;
        uint8_t *masked_field;
        if (header == OXM_OF_VLAN_VID){
            uint16_t m_value;
            sscanf(field->Value, "%hx", &m_value);
            m_value = (m_value  & VLAN_VID_MASK) >> VLAN_VID_SHIFT;
            ofl_structs_match_put16(pktout, header, m_value);
        }
        else if (header == OXM_OF_VLAN_PCP){
            uint16_t m_value;
            sscanf(field->Value, "%hx", &m_value);
            m_value = (m_value  & VLAN_PCP_MASK) >> VLAN_PCP_SHIFT;
            ofl_structs_match_put16(pktout, header, m_value);
        }
        else if(header == OXM_OF_IP_DSCP){
            uint8_t m_value;
            sscanf(field->Value, "%hhx", &m_value);
            m_value = (m_value & IP_DSCP_MASK) >> 2; 
            ofl_structs_match_put8(pktout, header, m_value);
        }
        else if(header == OXM_OF_IP_ECN){
            uint8_t m_value;
            sscanf(field->Value, "%hhx", &m_value);
            m_value = m_value & IP_ECN_MASK; 
            ofl_structs_match_put8(pktout, header, m_value);
        }
        else if(header == OXM_OF_MPLS_LABEL){
            uint32_t m_value;
            sscanf(field->Value, "%x", &m_value);
            m_value = (m_value & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT;
            ofl_structs_match_put32(pktout, header, m_value);
        }
        else if (header == OXM_OF_MPLS_TC){
            uint32_t m_value;
            sscanf(field->Value, "%x", &m_value);
            m_value = (m_value & MPLS_TC_MASK) >> MPLS_TC_SHIFT;
            ofl_structs_match_put8(pktout, header, m_value);
        }
        else if (header == OXM_OF_MPLS_BOS){
            uint32_t m_value;
            sscanf(field->Value, "%x", &m_value);
            m_value = (m_value & MPLS_S_MASK) >> MPLS_S_SHIFT;
            ofl_structs_match_put8(pktout, header, m_value);
        }
        else if (header == OXM_OF_PBB_ISID){
            uint32_t m_value;
            sscanf(field->Value, "%x", &m_value);
            m_value = (m_value & PBB_ISID_MASK);
            ofl_structs_match_put32(pktout, header, m_value);        
        }
        /*TODO: Add IPV6_FLABEL_SHIFT to lib/packets.h*/
        /*else if (header == OXM_OF_IPV6_FLABEL){
            uint32_t m_value;
            sscanf(field->Value, "%x", &m_value);
            m_value = (m_value & IPV6_FLABEL_MASK) >> IPV6_FLABEL_SHIFT;
            memcpy(pktout_field->value, &m_value, field->Size);

        }*/
    }
    else
    {
        switch (field->Size){
            case 1:{
                uint8_t m_value;
                sscanf(field->Value, "%hhx", &m_value);
                ofl_structs_match_put8(pktout, header, m_value);
                break;
            }
            case 2:{
                uint16_t m_value = *((uint16_t*)((uint8_t*)pktin->data + field->Position));
                m_value =  ntohs(m_value);  
                struct ofl_match_tlv *iter;
                if(header == OXM_OF_ETH_TYPE){
                    /*If Ethertype is already present we should not insert the next*/
                    HMAP_FOR_EACH_WITH_HASH(iter, struct ofl_match_tlv, hmap_node, hash_int(OXM_OF_ETH_TYPE, 0), &pktout->match_fields)
                    {
                        return 0;
                    }
                    /* Do not insert VLAN ethertypes*/
                    if(m_value == ETH_TYPE_VLAN || m_value == ETH_TYPE_SVLAN ||
                       m_value == ETH_TYPE_VLAN_QinQ || m_value == ETH_TYPE_VLAN_PBB_B){
                        return 0;
                    }
                }
                ofl_structs_match_put16(pktout, header, m_value);
                break;
            }
            case 4:{
                uint32_t m_value;

                if (header == OXM_OF_IPV4_DST || header == OXM_OF_IPV4_SRC ||
                            header == OXM_OF_ARP_SPA || header == OXM_OF_ARP_TPA){
                     m_value =   *((uint32_t*)((uint8_t*)pktin->data + field->Position));
                     ofl_structs_match_put32(pktout, header, m_value);
                }
                else {
                    m_value =  ntohl(*((uint32_t*)((uint8_t*)pktin->data + field->Position)));
                    ofl_structs_match_put32(pktout, header, m_value);
                }
                break;
            }
            case 6:{
                ofl_structs_match_put_eth(pktout, header,(uint8_t*)pktin->data + field->Position);
                break;
            }
            case 8:{
                uint64_t m_value =  *((uint64_t*)((uint8_t*)pktin->data + field->Position));
                m_value =  ntoh64(m_value);
                ofl_structs_match_put64(pktout, header, m_value);
                break;
            }
            case 16:{
                ofl_structs_match_put_ipv6(pktout, header,(uint8_t*)pktin->data + field->Position);
                break;
            }
        }

    }
    return 0;
}


extern "C" int nblink_packet_parse(struct ofpbuf * pktin,  struct ofl_match * pktout, struct protocols_std * pkt_proto)
{
    protocol_reset(pkt_proto);
    pkhdr->caplen = pktin->size; //need this information
    pkhdr->len = pktin->size; //need this information

    _nbPDMLPacket * curr_packet;

    ext_hdr_orders.insert( pair<uint16_t,uint16_t>(OFPIEH_HOP,HBH_ALLOWED));
    ext_hdr_orders.insert( pair<uint16_t,uint16_t>(OFPIEH_DEST,DESTINATION_ALLOWED));
    ext_hdr_orders.insert( pair<uint16_t,uint16_t>(OFPIEH_ROUTER,ROUTING_ALLOWED));
    ext_hdr_orders.insert( pair<uint16_t,uint16_t>(OFPIEH_FRAG,FRAG_ALLOWED));
    ext_hdr_orders.insert( pair<uint16_t,uint16_t>(OFPIEH_AUTH,AUTH_ALLOWED));
    ext_hdr_orders.insert( pair<uint16_t,uint16_t>(OFPIEH_ESP,ESP_ALLOWED));

    /* Decode packet */
    if (Decoder->DecodePacket(LinkLayerType, PacketCounter, pkhdr, (const unsigned char*) (pktin->data)) == nbFAILURE)
    {
        printf("\nError decoding a packet %s\n\n", Decoder->GetLastError());
        // Something went wrong
        return -1;
    }

    PDMLReader->GetCurrentPacket(&curr_packet);

    _nbPDMLProto * proto;
    _nbPDMLField * field;

    int destination_num = 0;
    proto = curr_packet->FirstProto;
    bool proto_done = true;
    while (proto!= NULL)
    {
        /* Getting first field of the protocol  */
            field = proto->FirstField;
            proto_done = false;
            string protocol_Name (proto->Name);
            string field_Name (field->Name);

            /* Copying data from the packet */

            if (protocol_Name.compare("ethernet") == 0 && pkt_proto->eth == NULL)
            {
                pkt_proto->eth = (struct eth_header *) ( (uint8_t*) pktin->data + proto->Position);
                PDMLReader->GetPDMLField(proto->Name, (char*) "dst", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_ETH_DST);
                PDMLReader->GetPDMLField(proto->Name, (char*) "src", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_ETH_SRC);
                PDMLReader->GetPDMLField(proto->Name, (char*) "type", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_ETH_TYPE);

            }
            else if ((protocol_Name.compare("vlan") == 0))
            {
                if(pkt_proto->vlan_last == NULL){
                    pkt_proto->vlan = pkt_proto->vlan_last = (struct vlan_header *) ((uint8_t*)  pktin->data + proto->Position);
                    PDMLReader->GetPDMLField(proto->Name, (char*) "pri", proto->FirstField, &field);
                    nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_VLAN_PCP);
                    PDMLReader->GetPDMLField(proto->Name, (char*) "vlanid", proto->FirstField, &field);
                    nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_VLAN_VID);
                    PDMLReader->GetPDMLField(proto->Name, (char*) "type", proto->FirstField, &field);
                    nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_ETH_TYPE);
                }
                else{
                    pkt_proto->vlan_last = (struct vlan_header *) ((uint8_t*)  pktin->data + proto->Position);
                    PDMLReader->GetPDMLField(proto->Name, (char*) "type", proto->FirstField, &field);
                    nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_ETH_TYPE);
                }

            }
            else if (protocol_Name.compare("mpls") == 0 && pkt_proto->mpls == NULL)
            {
                pkt_proto->mpls = (struct mpls_header *) ((uint8_t*) pktin->data + proto->Position);
                PDMLReader->GetPDMLField(proto->Name, (char*) "label", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_MPLS_LABEL);
                PDMLReader->GetPDMLField(proto->Name, (char*) "cos", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_MPLS_TC);
                PDMLReader->GetPDMLField(proto->Name, (char*) "bos", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_MPLS_BOS);
            }
            else if (protocol_Name.compare("arp") == 0 && pkt_proto->arp == NULL)
            {
                pkt_proto->arp = (struct arp_eth_header *) ((uint8_t*) pktin->data + proto->Position);
                PDMLReader->GetPDMLField(proto->Name, (char*) "op", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_ARP_OP);
                PDMLReader->GetPDMLField(proto->Name, (char*) "sHwAddr", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_ARP_SHA);
                PDMLReader->GetPDMLField(proto->Name, (char*) "sIPAddr", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_ARP_SPA);
                PDMLReader->GetPDMLField(proto->Name, (char*) "dHwAddr", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_ARP_THA);
                PDMLReader->GetPDMLField(proto->Name, (char*) "dIPAddr", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_ARP_TPA);

            }
            else if (protocol_Name.compare("pbb") == 0 && pkt_proto->pbb == NULL)
            {
                pkt_proto->pbb = (struct pbb_header *) ((uint8_t*) pktin->data + proto->Position);
                PDMLReader->GetPDMLField(proto->Name, (char*) "isid", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_PBB_ISID);
                PDMLReader->GetPDMLField(proto->Name, (char*) "type", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_ETH_TYPE);
            }
            if (protocol_Name.compare("ip") == 0 && pkt_proto->ipv4 == NULL)
            {
                pkt_proto->ipv4 = (struct ip_header *) ((uint8_t*) pktin->data + proto->Position);
                PDMLReader->GetPDMLField(proto->Name, (char*) "ip dscp", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_IP_DSCP);
                PDMLReader->GetPDMLField(proto->Name, (char*) "ip ecn", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_IP_ECN);
                PDMLReader->GetPDMLField(proto->Name, (char*) "src", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_IPV4_SRC);
                PDMLReader->GetPDMLField(proto->Name, (char*) "dst", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_IPV4_DST);
                PDMLReader->GetPDMLField(proto->Name, (char*) "nextp", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_IP_PROTO);
            }
            else if (protocol_Name.compare("ipv6") == 0 && pkt_proto->ipv6 == NULL)
            {
                _nbPDMLField * ip_proto = NULL;
                pkt_proto->ipv6 = (struct ipv6_header *) ((uint8_t*) pktin->data + proto->Position);
                PDMLReader->GetPDMLField(proto->Name, (char*) "flabel", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_IPV6_FLABEL);
                /*Initialize extension header OXM */
                struct ofl_match_tlv * EH_field;
                uint16_t bit_field = OFPIEH_NONEXT;
                uint8_t i;
                EH_field = (struct ofl_match_tlv *) malloc(sizeof(struct ofl_match_tlv));
                EH_field->value = (uint8_t*) malloc(OXM_LENGTH(OXM_OF_IPV6_EXTHDR));
                EH_field->header = OXM_OF_IPV6_EXTHDR;
                /*Set everything to zero */
                memset(EH_field->value,0x0, sizeof(uint16_t));

                char *pEnd;
                uint16_t next_header = strtol(field->Value, &pEnd,16);
                /*Set OFPIEH_NONEXT */
                if (next_header == IPV6_NO_NEXT_HEADER)
                {
                    uint16_t *ext_hdrs;

                    ext_hdrs = (uint16_t*) EH_field->value;
                    *ext_hdrs ^=  OFPIEH_NONEXT;
                    *ext_hdrs = *ext_hdrs;
                }

                hmap_insert_fast(&pktout->match_fields, &EH_field->hmap_node,
                            hash_int(EH_field->header, 0));
                pktout->header.length += 6;
                PDMLReader->GetPDMLField(proto->Name, (char*) "src", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_IPV6_SRC);
                PDMLReader->GetPDMLField(proto->Name, (char*) "dst", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_IPV6_DST);

                PDMLReader->GetPDMLField(proto->Name, (char*) "nexthdr", proto->FirstField, &ip_proto);

                if (PDMLReader->GetPDMLField(proto->Name, (char*) "HBH", proto->FirstField, &field) == nbSUCCESS){                    
                    nblink_extract_exthdr_fields(pktin, pktout, OFPIEH_HOP, field, &destination_num);
                    if(!field->NextField)
                        ip_proto = field->FirstChild;                    
                }
                if(PDMLReader->GetPDMLField(proto->Name, (char*) "FH", proto->FirstField, &field) == nbSUCCESS){
                    nblink_extract_exthdr_fields(pktin, pktout, OFPIEH_FRAG, field, &destination_num);
                    if(!field->NextField)
                        ip_proto = field->FirstChild;
                }
                if(PDMLReader->GetPDMLField(proto->Name, (char*) "AH",proto->FirstField, &field) == nbSUCCESS){
                    nblink_extract_exthdr_fields(pktin, pktout, OFPIEH_AUTH, field, &destination_num);
                    if(!field->NextField)
                        ip_proto = field->FirstChild;
                }
                if(PDMLReader->GetPDMLField(proto->Name, (char*) "DOH", proto->FirstField, &field) == nbSUCCESS){                   
                    nblink_extract_exthdr_fields(pktin, pktout, OFPIEH_DEST, field, &destination_num);
                    if(!field->NextField)
                        ip_proto = field->FirstChild;
                }
                if(PDMLReader->GetPDMLField(proto->Name, (char*) "RH", proto->FirstField, &field) == nbSUCCESS){
                    nblink_extract_exthdr_fields(pktin, pktout, OFPIEH_ROUTER, field, &destination_num);
                    if(!field->NextField)
                        ip_proto = field->FirstChild;
                }
                if(PDMLReader->GetPDMLField(proto->Name, (char*) "ESP", proto->FirstField, &field) == nbSUCCESS){                    
                    nblink_extract_exthdr_fields(pktin, pktout, OFPIEH_ESP, field, &destination_num);
                    if(!field->NextField)
                        ip_proto = field->FirstChild;
                }                
                if (ip_proto){
                    nblink_extract_proto_fields(pktin, ip_proto, pktout, OXM_OF_IP_PROTO);
                }
            }
            if (protocol_Name.compare("tcp") == 0 && pkt_proto->tcp == NULL)
            {
                pkt_proto->tcp = (struct tcp_header *) ((uint8_t*) pktin->data + proto->Position);
                PDMLReader->GetPDMLField(proto->Name, (char*) "sport", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_TCP_SRC);
                PDMLReader->GetPDMLField(proto->Name, (char*) "dport", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_TCP_DST);
            }
            else if (protocol_Name.compare("udp") == 0 && pkt_proto->udp == NULL)
            {
                pkt_proto->udp = (struct udp_header *) ((uint8_t*) pktin->data + proto->Position);
                PDMLReader->GetPDMLField(proto->Name, (char*) "sport", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_UDP_SRC);
                PDMLReader->GetPDMLField(proto->Name, (char*) "dport", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_UDP_DST);
            }
            else if (protocol_Name.compare("sctp") == 0 && pkt_proto->sctp == NULL)
            {
                pkt_proto->sctp = (struct sctp_header *) ((uint8_t*) pktin->data + proto->Position);
            }

            if (protocol_Name.compare("icmp") == 0 && pkt_proto->icmp == NULL){
                pkt_proto->icmp = (struct icmp_header *) ((uint8_t*) pktin->data + proto->Position);

                PDMLReader->GetPDMLField(proto->Name, (char*) "type", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_ICMPV4_TYPE);
                PDMLReader->GetPDMLField(proto->Name, (char*) "code", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_ICMPV4_CODE);
            }
            else if (protocol_Name.compare("icmp6") == 0 && pkt_proto->icmp == NULL){
                pkt_proto->icmp = (struct icmp_header *) ((uint8_t*) pktin->data + proto->Position);

                PDMLReader->GetPDMLField(proto->Name, (char*) "type", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_ICMPV6_TYPE);
                PDMLReader->GetPDMLField(proto->Name, (char*) "code", proto->FirstField, &field);
                nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_ICMPV6_CODE);
                if (PDMLReader->GetPDMLField(proto->Name, (char*) "NeighSol", proto->FirstField, &field) == nbSUCCESS ||
                    PDMLReader->GetPDMLField(proto->Name, (char*) "NeighAdv", proto->FirstField, &field) == nbSUCCESS){
                    PDMLReader->GetPDMLField(proto->Name, (char*) "target_address", proto->FirstField, &field);
                    nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_IPV6_ND_TARGET);
                }
                if (PDMLReader->GetPDMLField(proto->Name, (char*) "NDO", proto->FirstField, &field) == nbSUCCESS){
                    PDMLReader->GetPDMLField(proto->Name, (char*) "src link_layer_address", proto->FirstField, &field);
                    nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_IPV6_ND_SLL);
                    PDMLReader->GetPDMLField(proto->Name, (char*) "dst link_layer_address", proto->FirstField, &field);
                    nblink_extract_proto_fields(pktin, field, pktout, OXM_OF_IPV6_ND_TLL);
                }
            }
            while (!field->isField)
            {
            // This is necessary for Protocols with a Block as a first "field" on NetBee,
            // for instance the "vlan" protocol (see NetPDL for further details).
                field = field->FirstChild;            
            }
            if (field->NextField == NULL && field->ParentField != NULL)
            // If we are under a block with no more fields, return to the block and move on.
            {
                field = field->ParentField;

            }
            proto = proto->NextProto;

        }

    return 1;
}



