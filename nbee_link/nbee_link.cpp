/*
 * nbee_link.cpp
 *
 *  Created on: Jul 18, 2011
 *      Author: rdenicol
 */

#include <iostream>
#include <string.h>
#include <nbee/nbee.h>
#include <netinet/in.h>

#include "nbee_link.h"
#include "oflib/oxm-match.h"
#include "lib/hash.h"

nbPacketDecoder *Decoder;
nbPacketDecoderVars* PacketDecoderVars;
nbNetPDLLinkLayer_t LinkLayerType;
nbPDMLReader *PDMLReader;
int PacketCounter= 1;
struct pcap_pkthdr * pkhdr;

extern "C" int nblink_initialize(void)
{

    char ErrBuf[ERRBUF_SIZE + 1];
    int NetPDLProtoDBFlags = nbPROTODB_FULL;
    int NetPDLDecoderFlags = nbDECODER_GENERATEPDML_COMPLETE;
    int ShowNetworkNames = 0;

    char* NetPDLFileName = (char*) "customnetpdl.xml";

    pkhdr = new struct pcap_pkthdr;

    if (nbIsInitialized() == nbFAILURE)
    {
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
    bool done=0;
    HMAP_FOR_EACH(iter,struct packet_fields, hmap_node,pktout)
    {
        if(iter->header == pktout_field->header)
        {
            /* Adding entry to existing hash entry (for now, do this only to ethertype)*/
            memcpy(iter->value,((uint8_t*)pktin->data + pktout_field->pos),Size);
            free(pktout_field);
            done=1;
            break;
        }
    }
    if (!done)
    {
        /* Creating new hash map entry */
        hmap_insert_fast(pktout, &pktout_field->hmap_node,
        hash_int(pktout_field->header, 0));
    }
    return 0;
}

int nbee_extract_proto_fields(struct ofpbuf * pktin, _nbPDMLField * field, struct hmap * pktout )
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
        masked_field = (uint8_t * ) malloc(field->Size);
        uint32_t true_value = strtol(field->ShowValue,&pEnd,10);             	
        for (i=0;i<field->Size;i++)
        {
            masked_field[i] = (uint8_t)((true_value >> (8*(field->Size-i-1)) ) & 0xFF);
        }            	
        memcpy(pktout_field->value,((uint8_t*)masked_field),field->Size);
        free(masked_field);
    }
    else
    {
       memcpy(pktout_field->value,((uint8_t*)pktin->data + field->Position),field->Size);
    }
    nblink_add_entry_hmap(pktin,pktout,pktout_field,size);
    
    return 0;         	
}

extern "C" int nblink_packet_parse(struct ofpbuf * pktin,  struct hmap * pktout, struct protocols_std * pkt_proto)
{
    protocol_reset(pkt_proto);
	pkhdr->caplen = pktin->size; //need this information
	pkhdr->len = pktin->size; //need this information

	_nbPDMLPacket * curr_packet;

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

	proto = curr_packet->FirstProto;
    bool proto_done = true;
    while (1)
    {
        /* Getting first field of the protocol  */
        
        if(proto_done)
        {
            field = proto->FirstField;
            proto_done = false;
            
            /* Any other way of doing this?!?! */
            /* ============== start ================ */
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
            }
            else if (protocol_Name.compare("vlan") == 0 && pkt_proto->vlan == NULL)
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
            /* ============== end ================ */
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
            nbee_extract_proto_fields(pktin,field,pktout);
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
	            pktout_field->pos = (uint32_t) field->Position;

                char * pEnd;
	            vendor = strtol(field->NextField->LongName+1,&pEnd,0);
	            type = (uint32_t) (vendor<<7)+(strtol(pEnd,NULL,10));
                pktout_field->value = (uint8_t*) malloc(field->Size);
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
                    pktout_field->header = OXM_HEADER(VENDOR_FROM_TYPE(type),FIELD_FROM_TYPE(type),nbPrevField->Size);
                    memcpy(pktout_field->value,((uint8_t*)pktin->data + nbPrevField->Position),nbPrevField->Size);
                    pktout_field->pos = (uint32_t) nbPrevField->Position;
                   	nblink_add_entry_hmap(pktin, pktout , pktout_field, (int) field->Size);
                    
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

