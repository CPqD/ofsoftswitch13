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

#include "nbee_link.h"
#include "oflib/oxm-match.h"
#include "lib/hash.h"

map<uint16_t,uint16_t> ext_hdr_orders;

nbPacketDecoder *Decoder;
nbPacketDecoderVars* PacketDecoderVars;
nbNetPDLLinkLayer_t LinkLayerType;
nbPDMLReader *PDMLReader;
int PacketCounter= 1;
struct pcap_pkthdr * pkhdr;


#define NETPDLFILE "customnetpdl.xml"

extern "C" int nblink_initialize(void)
{

    char ErrBuf[ERRBUF_SIZE + 1];
    int NetPDLProtoDBFlags = nbPROTODB_FULL;
    int NetPDLDecoderFlags = nbDECODER_GENERATEPDML_COMPLETE;
    int ShowNetworkNames = 0;

    char* NetPDLFileName = (char*) NETPDLDIR"/"NETPDLFILE;
    struct stat netpdlstat;

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
    //	PacketDecoderVars->SetVariableNumber((char*) NETPDL_VARIABLE_SHOWNETWORKNAMES, ShowNetworkNames);

    if (PacketDecoderVars->SetVariableNumber((char*) NETPDL_VARIABLE_SHOWNETWORKNAMES, ShowNetworkNames)==nbFAILURE)
    {
	    printf("Error: cannot set variables of the decoder properly.\n");
	    return nbFAILURE;
    }

    PDMLReader = Decoder->GetPDMLReader();

    return 0;

}

int nblink_add_entry_hmap(struct ofpbuf * pktin, struct hmap * pktout ,struct packet_fields * pktout_field, int Size)
/*
* This will add a field entry to the hash map structure.
*/
{
    struct packet_fields *iter;

    if(pktout_field->header == OXM_OF_ETH_TYPE){
        /*If Ethertype is already present we should not insert the next*/
        HMAP_FOR_EACH_WITH_HASH(iter, struct packet_fields, hmap_node, hash_int(OXM_OF_ETH_TYPE, 0), pktout)
        {
            return 0;
        } 
        /* Do not insert VLAN ethertypes*/
        uint16_t *eth_type = (uint16_t*) malloc(sizeof(uint16_t));
        memcpy(eth_type,pktout_field->value, Size);        
        if(*eth_type == ETH_TYPE_VLAN || *eth_type == ETH_TYPE_SVLAN ||
           *eth_type == ETH_TYPE_VLAN_QinQ || *eth_type == ETH_TYPE_VLAN_PBB_B){
            return 0;
        }
        free(eth_type);
    } 
    /* Creating new hash map entry */
    hmap_insert_fast(pktout, &pktout_field->hmap_node,hash_int(pktout_field->header, 0));
    
    return 0;
}

int nblink_check_for_entry_on_hmap(struct hmap * pktout ,uint32_t  header, struct packet_fields * field)
/*
* This search for an entry on the hmap and points field to it. 
* If no entry is found, -1 is returned.
*/
{
    struct packet_fields *iter;
    bool done=0;
    HMAP_FOR_EACH(iter,struct packet_fields, hmap_node,pktout)
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

int nblink_extract_proto_fields(struct ofpbuf * pktin, _nbPDMLField * field, struct hmap * pktout )
/* 
* Function used to extract a field from the NetBee field structure.
*/
{
/* Found a NetPDL field usable on matching */

    uint32_t type,vendor;
    uint8_t size;
    /* Preparing the internal structure */
    struct packet_fields * pktout_field;
    pktout_field = (struct packet_fields *) malloc(sizeof(struct packet_fields));

    pktout_field->pos = (uint32_t) field->Position;
	
    /* Decoding the field's type from the NetPDL structure */

    char * pEnd;
    vendor = strtol(field->LongName+1,&pEnd,0);
    type = (uint32_t) (vendor<<7)+(strtol(pEnd,NULL,10));
    size = field->Size;

    /* Copying data from the packet */
    pktout_field->header = OXM_HEADER(VENDOR_FROM_TYPE(type),FIELD_FROM_TYPE(type),size); 
    pktout_field->value = (uint8_t*) malloc(field->Size);
    if (field->Mask != NULL)
    {
        uint8_t i;
        uint8_t *masked_field;
        masked_field = (uint8_t *) malloc(field->Size);
        uint32_t true_value = strtol(field->ShowValue,&pEnd,10);             	
        for (i=0;i<field->Size;i++)
        {
            masked_field[i] = (uint8_t)((true_value >> (8*(field->Size-i-1)) ) & 0xFF);
        }    
        memcpy(pktout_field->value, masked_field,field->Size);
        
        free(masked_field);
    }
    else
    {        
       memcpy(pktout_field->value, ((uint8_t*)pktin->data + field->Position), field->Size);
    }

    nblink_add_entry_hmap(pktin, pktout,pktout_field, size);
    
    return 0;         	
}

/* 
* Function used to extract an Extension Header flag from the NetBee field structure.
*/
int nblink_extract_exthdr_fields(struct ofpbuf * pktin, struct hmap * pktout, _nbPDMLField * field, int *destination_num)
{    
    struct packet_fields *iter;
    uint16_t type;
    uint16_t *ext_hdrs; 
    if(!strcmp(field->Name, "HBH"))
        type = OFPIEH_HOP;
    else if(!strcmp(field->Name, "DOH")){
        type = OFPIEH_DEST;        
        (*destination_num)++;
    }    
    else if (!strcmp(field->Name, "RH"))
        type = OFPIEH_ROUTER;
    else if (!strcmp(field->Name, "FH"))
        type = OFPIEH_FRAG;
    else if (!strcmp(field->Name, "AH"))
        type = OFPIEH_AUTH;
    else if (!strcmp(field->Name, "ESP"))
        type = OFPIEH_ESP;

    HMAP_FOR_EACH_WITH_HASH(iter, struct packet_fields, hmap_node, hash_int(OXM_OF_IPV6_EXTHDR, 0), pktout)
    {
        /*First check if is duplicated*/
        ext_hdrs = (uint16_t*) iter->value;
        *ext_hdrs = ntohs(*ext_hdrs);
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
            if(!(it->second & next_type))   
                /*Set the not in order preferred bit */
                *ext_hdrs ^=  OFPIEH_UNSEQ;
        }

        /* Set the extension header flag*/
        *ext_hdrs ^=  type;
        *ext_hdrs = htons(*ext_hdrs);
    } 
    
    return 0;

}
extern "C" int nblink_packet_parse(struct ofpbuf * pktin,  struct hmap * pktout, struct protocols_std * pkt_proto)
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
    
    //struct timeval start, end;

    //gettimeofday(&start, NULL);
	/* Decode packet */
	if (Decoder->DecodePacket(LinkLayerType, PacketCounter, pkhdr, (const unsigned char*) (pktin->data)) == nbFAILURE)
	{
		printf("\nError decoding a packet %s\n\n", Decoder->GetLastError());
		// Something went wrong
		return -1;
	}
    /*gettimeofday(&end, NULL);        

    printf("Elapsed time %ld\n", ((end.tv_sec * 1000000 + end.tv_usec)
                  - (start.tv_sec * 1000000 + start.tv_usec)));*/

	PDMLReader->GetCurrentPacket(&curr_packet);

	_nbPDMLProto * proto;
	_nbPDMLField * field;

    int destination_num = 0;
	proto = curr_packet->FirstProto;
    bool proto_done = true;
    while (1)
    {
        /* Getting first field of the protocol  */
        if(proto_done)
        {
            field = proto->FirstField;
            proto_done = false;
            string protocol_Name (proto->Name);
            string field_Name (field->Name) ;
            if (protocol_Name.compare("ethernet") == 0 && pkt_proto->eth == NULL)
            {
                pkt_proto->eth = (struct eth_header *) ( (uint8_t*) pktin->data + proto->Position);
            }
            else if (protocol_Name.compare("ip") == 0 && pkt_proto->ipv4 == NULL)
            {
                pkt_proto->ipv4 = (struct ip_header *) ((uint8_t*) pktin->data + proto->Position);
            }
            else if (protocol_Name.compare("ipv6") == 0 && pkt_proto->ipv6 == NULL)
            {
                pkt_proto->ipv6 = (struct ipv6_header *) ((uint8_t*) pktin->data + proto->Position);
                struct packet_fields * EH_field;
                uint16_t bit_field = OFPIEH_NONEXT;
                uint8_t i;
                EH_field = (struct packet_fields *) malloc(sizeof(struct packet_fields));
                EH_field->value = (uint8_t*) malloc(OXM_LENGTH(OXM_OF_IPV6_EXTHDR));
                EH_field->header = OXM_OF_IPV6_EXTHDR;
                EH_field->pos = 0; //No valid value for this field
                /*Set everything to zero */
                memset(EH_field->value,0x0, sizeof(uint16_t));
                hmap_insert_fast(pktout, &EH_field->hmap_node,
                            hash_int(EH_field->header, 0));

            }
            else if ((protocol_Name.compare("vlan") == 0 || protocol_Name.compare("pbb_b") == 0) && pkt_proto->vlan == NULL)
            {
                pkt_proto->vlan = (struct vlan_header *) ((uint8_t*)  pktin->data + proto->Position);
            }
            else if (protocol_Name.compare("mpls") == 0 && pkt_proto->mpls == NULL)
            {
                pkt_proto->mpls = (struct mpls_header *) ((uint8_t*) pktin->data + proto->Position);
            }
            else if (protocol_Name.compare("tcp") == 0 && pkt_proto->tcp == NULL)
            {
                pkt_proto->tcp = (struct tcp_header *) ((uint8_t*) pktin->data + proto->Position);
            }
            else if (protocol_Name.compare("arp") == 0 && pkt_proto->arp == NULL)
            {
                pkt_proto->arp = (struct arp_eth_header *) ((uint8_t*) pktin->data + proto->Position);
            }
            else if (protocol_Name.compare("pbb_s") == 0 && pkt_proto->pbb == NULL)
            {
                pkt_proto->pbb = (struct pbb_header *) ((uint8_t*) pktin->data + proto->Position);
            }
//          else if (protocol_Name.compare("pbb_b") == 0 && pkt_proto->pbb_b == NULL)
//          {
//                pkt_proto->pbb_b = (struct pbb_b_header *) ((uint8_t*) pktin->data + proto->Position);
//           }
            while (!field->isField)
            {
            // This is necessary for Protocols with a Block as a first "field" on NetBee,
            // for instance the "vlan" protocol (see NetPDL for further details).
                field = field->FirstChild;
            }
        }

        if ((char)field->LongName[0]=='{')
        {
        // The '{' character identifies fields we use on matching.
            if (field->ShowValue != NULL)
            {            
                nblink_extract_proto_fields(pktin,field,pktout);
            }
            else
            {
               // cout << "field->Name == " << field->Name << " size: " << field->Size << " no value"<< endl;
            }
            
        }
        

        // From here on, we check what's ahead, if the packet is done, continue.
        if(field->NextField == NULL && field->ParentField == NULL)
        {
            /* Protocol Done */
            if (proto->NextProto == NULL)
		    {
                /* Packet Done */
			    break;
		    }
            proto = proto->NextProto;
            proto_done = true;
        }
        else if (field->NextField == NULL && field->ParentField != NULL)
        // If we are under a block with no more fields, return to the block and move on.
        {
            field = field->ParentField;
            
        }
        else if (!field->NextField->isField)
        // If the next field is a block, we need to check if it is used on matching.
        {
            if ((char)field->NextField->LongName[0] == '{')
            // This block has an identifier (probably an IPv6 EH)
            {
            /* Found a NetPDL Block usable on matching */
                uint32_t type,vendor;
	            struct packet_fields * pktout_field;
	            
	            pktout_field = (struct packet_fields *) malloc(sizeof(struct packet_fields));
	            pktout_field->pos = (uint32_t) field->NextField->Position;

                char * pEnd;
	            vendor = strtol(field->NextField->LongName+1,&pEnd,0);
	            type = (uint32_t) (vendor<<7)+(strtol(pEnd,NULL,10));
                pktout_field->value = (uint8_t*) malloc(field->NextField->Size);
                _nbPDMLField * nbPrevField; 

                if( !field->isField)
                    nbPrevField = field->NextField->FirstChild;
                else
                    nbPrevField = proto->FirstField;
    
                string NextHeader ("nexthdr");
                bool found = true;
                while(NextHeader.compare(nbPrevField->Name))
                {
                    if(nbPrevField->NextField != NULL)
                    {
                        nbPrevField = nbPrevField->NextField;
                    }
                    else
                    {
                        found = false ;
                        break;
                    }
                }

                if (found)
                {
                    /* We found our field... If it is an IPv6 
                     * EH we should set the corresponding
                     * bit on the hmap entry to 1. 
                     */
                    if (type == OXM_TYPE(OXM_OF_IPV6_EXTHDR))
                    {
                        nblink_extract_exthdr_fields(pktin,pktout, field->NextField, &destination_num);
                        free(pktout_field);
                    }
                    else
                    {
                        pktout_field->header = OXM_HEADER(VENDOR_FROM_TYPE(type),FIELD_FROM_TYPE(type),nbPrevField->Size);
                        memcpy(pktout_field->value,((uint8_t*)pktin->data + nbPrevField->Position),nbPrevField->Size);
                        pktout_field->pos = (uint32_t) nbPrevField->Position;
                       	nblink_add_entry_hmap(pktin, pktout , pktout_field, (int) field->Size);
                    }
                }
            }
            /* Next field is a block. */
            field = field->NextField->FirstChild;
        }			
        else
        {
            field = field->NextField;
        }
	} 
    
	return 1;
}

