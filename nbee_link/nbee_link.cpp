/*
 * nbee_link.cpp
 *
 *  Created on: Jul 18, 2011
 *      Author: rdenicol
 */

#include <iostream>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <nbee.h>
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
    bool done=0;
    HMAP_FOR_EACH(iter,struct packet_fields, hmap_node,pktout)
    {
        if(OXM_TYPE(iter->header) == OXM_TYPE(pktout_field->header))
        {
            if(OXM_LENGTH(iter->header) != OXM_LENGTH(pktout_field->header))
            {
                printf("Wrong Length\n");
                break;
            }
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
int nblink_initialize_EH_hmap_entry (struct hmap * pktout)
{
    struct packet_fields * pktout_field;
    uint16_t value = OFPIEH_NONEXT;
    uint8_t i;
    
    pktout_field->header = OXM_OF_IPV6_EXTHDR;
    pktout_field->pos = 0;
    
    for (i=0;i<sizeof(value);i++)
    {
        pktout_field->value[i] = (uint8_t)((value >> (8*(sizeof(value)-i-1)) ) & 0xFF);
    }

//    nblink_add_entry_hmap(pktin,pktout,pktout_field,size);
    hmap_insert_fast(pktout, &pktout_field->hmap_node,
                        hash_int(pktout_field->header, 0));    
    
    return 0;
    
}
int nblink_extract_exthdr_fields(struct ofpbuf * pktin, struct hmap * pktout, _nbPDMLField * field, struct control_eh_fields * control_EH)
/* 
* Function used to extract an Extension Header flag from the NetBee field structure.
*/
{
    uint32_t type,vendor, field_shift, field_position_aux;
    uint8_t i;
    uint16_t ipv6_exthdr;
    
    struct packet_fields * new_field;

    /* Decoding the field's type and Extension Header ID from the NetPDL structure */
    char * pEnd;
    vendor = strtol(field->LongName+1,&pEnd,0);
    type = (uint32_t) (vendor<<7)+(strtol(pEnd,&pEnd,10));
    field_shift = strtol(pEnd,&pEnd,10);
    field_position_aux = strtol(pEnd,NULL,10);
    ipv6_exthdr = (uint16_t) (1 << (field_shift));
    printf("VENDOR: %d FIELD: %d SHIFT: %d\n",vendor,FIELD_FROM_TYPE(type),field_shift);

    new_field = (struct packet_fields *) malloc(sizeof(struct packet_fields));
    new_field->header = OXM_HEADER(VENDOR_FROM_TYPE(type),FIELD_FROM_TYPE(type),field->Size); 
    new_field->value = (uint8_t*) malloc(sizeof(uint16_t));
    
    if(ipv6_exthdr == OFPIEH_DEST && control_EH->count_DOEH>0)
    {
        control_EH->position_EH[7] = (uint32_t) field->Position;
    }
    else
    {
        control_EH->position_EH[field_position_aux] = field->Position;
    }
    struct packet_fields *iter;
    bool found=0;
    HMAP_FOR_EACH(iter,struct packet_fields, hmap_node,pktout)
    {
        if(OXM_TYPE(iter->header) == OXM_TYPE(new_field->header))
        {
            found = 1;
            break;
        }
    }
/*    int ret= 0;
    ret = nblink_check_for_entry_on_hmap(pktout ,OFPXMT_OFB_IPV6_EXTHDR , iter);
    if (ret < 0)
    {
*/
    if (!found)
    {
        for (i=0;i<sizeof(uint16_t);i++)
        {
            new_field->value[i] = (uint8_t)((ipv6_exthdr >> (8*(sizeof(uint16_t)-i-1)) ) & 0xFF);
        }
        hmap_insert_fast(pktout, &new_field->hmap_node,
        hash_int(new_field->header, 0));
        printf("<1> EH Value: %d On HMAP: %02x%02x\n",ipv6_exthdr,new_field->value[0],new_field->value[1]);
        //cout << "<1> EH Value: " << ipv6_exthdr << " On HMAP: " << new_field->value[0] << new_field->value[1] << endl;
//        nblink_add_entry_hmap(pktin,pktout,new_field,sizeof(uint16_t));
    }
    else
    {
        
        uint16_t old_ipv6_exthdr = 0;
        for (i=0;i<field->Size;i++)
        {
            old_ipv6_exthdr = old_ipv6_exthdr ^ ((uint16_t)(iter->value[i])) << (8*(field->Size-i-1));
        }
//        memcpy((uint8_t*)&old_ipv6_exthdr, new_field->value,new_field->Size);
        /* TODO : check if the bits set on this structure are field bits and not control bits.
         * Also, check if this works at all as it should.
         */ 
        if (old_ipv6_exthdr & ipv6_exthdr == ipv6_exthdr)
        {
        // Repeated Extension Header Field
            
            if (ipv6_exthdr == OFPIEH_DEST)
            {
                control_EH->count_DOEH++ ;
                if ( control_EH->count_DOEH >2 && old_ipv6_exthdr & OFPIEH_UNREP == 0)
                {
                    ipv6_exthdr = ipv6_exthdr ^ OFPIEH_UNREP ;
                }
            }
            else if (old_ipv6_exthdr & OFPIEH_UNREP == 0 )
            {
                ipv6_exthdr = ipv6_exthdr ^ OFPIEH_UNREP ;
            }
            
        }
        else
        {
        // New Extension Header Field
            if (ipv6_exthdr == OFPIEH_DEST)
            {
                control_EH->count_DOEH++ ;
            }
            
            ipv6_exthdr = old_ipv6_exthdr ^ ipv6_exthdr ;
        }
        
        
        for (i=0;i<field->Size;i++)
        {
            new_field->value[i] = (uint8_t)((ipv6_exthdr >> (8*(sizeof(uint16_t)-i-1)) ) & 0xFF);
        }
        printf("<2> EH Value: %d On HMAP: %02x%02x\n",ipv6_exthdr,new_field->value[0],new_field->value[1]);
//        cout << "<2> EH Value: " << ipv6_exthdr << " On HMAP: " << new_field->value[0] << new_field->value[1]  << endl;
        memcpy(iter->value,new_field->value,field->Size);

    }
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

    struct control_eh_fields * control_EH;
    control_EH = (struct control_eh_fields *) malloc(sizeof(struct control_eh_fields));
    
    control_EH->count_DOEH = 0;
    uint8_t j;
    for (j=0;j<10;j++)
    {
        control_EH->position_EH[j]=0;
    }

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
                /* TODO Initialize a hmap entry for the EH with OFPIEH_NONEXT*/
                struct packet_fields * EH_field;
                uint16_t bit_field = OFPIEH_NONEXT;
                uint8_t i;
                EH_field = (struct packet_fields *) malloc(sizeof(struct packet_fields));
                EH_field->value = (uint8_t*) malloc(OXM_LENGTH(OXM_OF_IPV6_EXTHDR));
                EH_field->header = OXM_OF_IPV6_EXTHDR;
                EH_field->pos = 0; //No valid value for this field
                for (i=0;i<field->Size;i++)
                {
                    EH_field->value[i] = (uint8_t)((bit_field >> 
                            (8*(OXM_LENGTH(OXM_OF_IPV6_EXTHDR)-i-1)) ) & 0xFF);
                }
                printf("<3> EH Value: %d On HMAP: %02x%02x\n",bit_field,EH_field->value[0],EH_field->value[1]);
                //cout << "<3> EH Value: " << bit_field << " On HMAP: " << EH_field->value[0] << EH_field->value[1]  << endl;
                hmap_insert_fast(pktout, &EH_field->hmap_node,
                            hash_int(EH_field->header, 0));
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
            else if (protocol_Name.compare("pbb_s") == 0 && pkt_proto->pbb == NULL)
            {
                pkt_proto->pbb = (struct pbb_header *) ((uint8_t*) pktin->data + proto->Position);
            }
//            else if (protocol_Name.compare("pbb_b") == 0 && pkt_proto->pbb_b == NULL)
//            {
//                pkt_proto->pbb_b = (struct pbb_b_header *) ((uint8_t*) pktin->data + proto->Position);
//            }
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
                cout << "field->Name == " << field->Name << " size: " << field->Size << " Value: " <<
            field->ShowValue << endl;
                nblink_extract_proto_fields(pktin,field,pktout);
            }
            else
            {
                cout << "field->Name == " << field->Name << " size: " << field->Size << " no value"<< endl;
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
                        printf("TYPE 39 \n");
                        nblink_extract_exthdr_fields(pktin,pktout, field->NextField, control_EH);
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
	struct packet_fields * iter;
	uint8_t i = 0;
    uint8_t unseq = 0;
    
    for (i=0;i<9;i++)
    {
        if (control_EH->position_EH[i] != 0)
        {
            for(j=i+1;j<10;j++)
            {
                if (control_EH->position_EH[j] != 0 &&
                    control_EH->position_EH[i] > control_EH->position_EH[j])
                    {
                        HMAP_FOR_EACH(iter,struct packet_fields, hmap_node,pktout)
                        {
                            if (OXM_TYPE(iter->header) == OXM_TYPE(OXM_OF_IPV6_EXTHDR))
                            {
                                uint16_t k,ipv6_exthdr = 0;
                                unseq = 1;
                                for (k=0;k<OXM_LENGTH(OXM_OF_IPV6_EXTHDR);k++)
                                {
                                    ipv6_exthdr = ipv6_exthdr ^ ((uint16_t)(iter->value[k])) << (8*(OXM_LENGTH(OXM_OF_IPV6_EXTHDR)-k-1));
                                }
                                if ((ipv6_exthdr & OFPIEH_UNSEQ) == 0)
                                {
                                    ipv6_exthdr = ipv6_exthdr ^ OFPIEH_UNSEQ;
                                }
                                for (k=0;k<OXM_LENGTH(OXM_OF_IPV6_EXTHDR);k++)
                                {
                                    iter->value[k] = (uint8_t)((ipv6_exthdr >> (8*(OXM_LENGTH(OXM_OF_IPV6_EXTHDR)-k-1)) ) & 0xFF);
                                }
                                
                            }
                        }
                    }
                if (unseq == 1)
                {
                    break;
                }
            }
        }
        if (unseq == 1)
        {
            break;
        }        
    }   
    
    for (i=0;i<9;i++)
    {
        printf("pos %d : %d | ",i, control_EH->position_EH[i]);    
    }
    printf("\n");
    
    HMAP_FOR_EACH(iter,struct packet_fields, hmap_node,pktout)
    {
        
        printf("HMap entry vendor %d type %d value ",OXM_VENDOR(iter->header),OXM_FIELD(iter->header));
        for (i=0;i<OXM_LENGTH(iter->header);i++)
        {
            printf("%02x",iter->value[i]);
        }
        printf("\n");
        
    }

    
	return 1;
}

