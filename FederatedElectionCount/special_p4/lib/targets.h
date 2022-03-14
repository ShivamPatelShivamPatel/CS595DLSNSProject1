#ifndef TARGETS_H_
#define TARGETS_H_

extern void drop();

/*********
 * IF THE TARGET IS THE P4 BEHAVIORAL MODEL
 *********/
#if defined(TARGET_BMV2)
#include "v1model.p4"
#include "Parsing.p4"

// Hardware port size
#define PORT_SIZE 9

// Metadata and interface to egress port
#define metadata_t standard_metadata_t
#define SET_EGRESS(meta, port) meta.egress_spec = port

#else // defined(TARGET_BMV2)
#error("No target defined")
#endif

#endif //TARGETS_H_
