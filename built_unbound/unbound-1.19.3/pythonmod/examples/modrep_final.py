import os

def init(id, cfg):
    return True

def deinit(id):
    return True

def inform_super(id, qstate, superqstate, qdata):
    return True

def setTTL(qstate, ttl):
    """Updates return_msg TTL and the TTL of all the RRs"""
    if qstate.return_msg:
        qstate.return_msg.rep.ttl = ttl
        if qstate.return_msg.rep:
            for i in range(qstate.return_msg.rep.rrset_count):
                d = qstate.return_msg.rep.rrsets[i].entry.data
                for j in range(d.count + d.rrsig_count):
                    d.rr_ttl[j] = ttl

def createAuthResponseSimple(qstate, id, rr_type, rr_data):
    """Creates an authoritative DNS response with the specified RR type and data."""
    msg = DNSMessage(qstate.qinfo.qname_str, rr_type, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
    
    # Add the specified RR to the response
    if rr_type == RR_TYPE_A:
        msg.answer.append(f"{qstate.qinfo.qname_str} 10 IN A {rr_data}")
    elif rr_type == RR_TYPE_AAAA:
        msg.answer.append(f"{qstate.qinfo.qname_str} 10 IN AAAA {rr_data}")
    elif rr_type == RR_TYPE_CNAME:
        msg.answer.append(f"{qstate.qinfo.qname_str} 10 IN CNAME {rr_data}")
    elif rr_type == RR_TYPE_NS:
        msg.answer.append(f"{qstate.qinfo.qname_str} 10 IN NS {rr_data}")
    elif rr_type == RR_TYPE_MX:
        msg.answer.append(f"{qstate.qinfo.qname_str} 10 IN MX {rr_data}")
    elif rr_type == RR_TYPE_TXT:
        msg.answer.append(f"{qstate.qinfo.qname_str} 10 IN TXT \"{rr_data}\"")
    else:
        qstate.ext_state[id] = MODULE_ERROR
        return False

    # Set qstate.return_msg
    if not msg.set_return_msg(qstate):
        qstate.ext_state[id] = MODULE_ERROR
        return False

    # We don't need validation, the result is valid
    qstate.return_msg.rep.security = 2
    qstate.return_rcode = RCODE_NOERROR
    qstate.ext_state[id] = MODULE_FINISHED
    return True

def deleteRR(qstate, id):
        """Delete all RRs in the current response by clearing the rrsets."""
        if qstate.return_msg and qstate.return_msg.rep:
            # Replace the rrsets with an empty list
            qstate.return_msg.rep.rrsets = []
            qstate.return_msg.rep.rrset_count = 0
    
            # Mark the response as no error and the module as finished
            qstate.return_rcode = RCODE_NOERROR
            qstate.ext_state[id] = MODULE_FINISHED
        else:
            qstate.ext_state[id] = MODULE_ERROR
        return True

def addRR(qstate, id, rr_type, rr_data):
    """Add a Resource Record to the current response"""
    if not qstate.return_msg:
        qstate.ext_state[id] = MODULE_ERROR
        return False

    # Initialize the DNS message if not already done
    msg = qstate.return_msg

    if not hasattr(msg, 'answer') or msg.answer is None:
        msg.answer = []

    # Add the specified RR to the response
    if rr_type == RR_TYPE_A:
        msg.answer.append(f"{qstate.qinfo.qname_str} 10 IN A {rr_data}")
    elif rr_type == RR_TYPE_AAAA:
        msg.answer.append(f"{qstate.qinfo.qname_str} 10 IN AAAA {rr_data}")
    elif rr_type == RR_TYPE_CNAME:
        msg.answer.append(f"{qstate.qinfo.qname_str} 10 IN CNAME {rr_data}")
    elif rr_type == RR_TYPE_NS:
        msg.answer.append(f"{qstate.qinfo.qname_str} 10 IN NS {rr_data}")
    elif rr_type == RR_TYPE_MX:
        msg.answer.append(f"{qstate.qinfo.qname_str} 10 IN MX {rr_data}")
    elif rr_type == RR_TYPE_TXT:
        msg.answer.append(f"{qstate.qinfo.qname_str} 10 IN TXT \"{rr_data}\"")
    else:
        qstate.ext_state[id] = MODULE_ERROR
        return False

    # Manually assign the modified message to the qstate return message
    qstate.return_msg = msg

    qstate.return_msg.rep.security = 2
    qstate.return_rcode = RCODE_NOERROR
    qstate.ext_state[id] = MODULE_FINISHED
    return True

def changeRRType(qstate, id, new_rr_type, new_rr_data):
    """Change the RR type in the current response"""
    if not qstate.return_msg:
        qstate.ext_state[id] = MODULE_ERROR
        return False

    msg = qstate.return_msg
    # Clear the current RRs and add the new RR with the new type
    msg.answer = []
    addRR(qstate, id, new_rr_type, new_rr_data)

def operate(id, event, qstate, qdata):
    if event in [MODULE_EVENT_NEW, MODULE_EVENT_PASS]:
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    if event == MODULE_EVENT_MODDONE:
        log_info("pythonmod: iterator module done")

        if not qstate.return_msg:
            qstate.ext_state[id] = MODULE_FINISHED
            return True

        if os.path.exists("task_params.txt"):
            with open("task_params.txt", "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split()
                    task_type = int(parts[0])
                    domain = parts[1]

                    if task_type in [0, 1, 2, 3] and len(parts) > 2:
                        ttl = int(parts[2])
                        setTTL(qstate, ttl)

                    if task_type in [4, 5, 6, 7, 8, 9] and len(parts) > 3:
                        rr_type = None
                        if task_type == 4:
                            rr_type = RR_TYPE_A
                        elif task_type == 5:
                            rr_type = RR_TYPE_AAAA
                        elif task_type == 6:
                            rr_type = RR_TYPE_CNAME
                        elif task_type == 7:
                            rr_type = RR_TYPE_NS
                        elif task_type == 8:
                            rr_type = RR_TYPE_MX
                        elif task_type == 9:
                            rr_type = RR_TYPE_TXT

                        rr_data = " ".join(parts[3:])
                        createAuthResponseSimple(qstate, id, rr_type, rr_data)

                    elif task_type in [10, 11, 12, 13, 14, 15]:
                        rr_type = None
                        if task_type == 10:
                            rr_type = RR_TYPE_A
                        elif task_type == 11:
                            rr_type = RR_TYPE_AAAA
                        elif task_type == 12:
                            rr_type = RR_TYPE_CNAME
                        elif task_type == 13:
                            rr_type = RR_TYPE_NS
                        elif task_type == 14:
                            rr_type = RR_TYPE_MX
                        elif task_type == 15:
                            rr_type = RR_TYPE_TXT
                        
                        rr_data = " ".join(parts[3:])
                        addRR(qstate, id, rr_type, rr_data)

                    elif task_type in [16, 17, 18, 19, 20, 21]:
                        new_rr_type = None
                        if task_type == 16:
                            new_rr_type = RR_TYPE_A
                        elif task_type == 17:
                            new_rr_type = RR_TYPE_AAAA
                        elif task_type == 18:
                            new_rr_type = RR_TYPE_CNAME
                        elif task_type == 19:
                            new_rr_type = RR_TYPE_NS
                        elif task_type == 20:
                            new_rr_type = RR_TYPE_MX
                        elif task_type == 21:
                            new_rr_type = RR_TYPE_TXT

                        new_rr_data = " ".join(parts[3:])
                        changeRRType(qstate, id, new_rr_type, new_rr_data)

                    elif task_type == 22:
                        deleteRR(qstate, id)
                    elif task_type == 23:
                        # Change domain name to "www.phishylink.com"
                        changeRRType(qstate, id, qstate.qinfo.qtype, "www.phishylink.com")
                    elif task_type == 24:
                        # Change IP address to "192.168.0.1"
                        changeRRType(qstate, id, RR_TYPE_A, "192.168.0.1")
                    elif task_type == 25:
                        # Append duplicate RRs with changed IP address
                        if qstate.return_msg:
                            rr_type = qstate.qinfo.qtype
                            rr_data = "192.168.0.1"
                            addRR(qstate, id, rr_type, rr_data)
                    elif task_type == 26:
                        # Randomly modify optional fields
                        if qstate.return_msg and qstate.return_msg.rep:
                            qstate.return_msg.rep.flags ^= 0x0100  # Toggle some flag as an example
                    elif task_type == 27:
                        # Change delimiter formats
                        if qstate.return_msg and qstate.return_msg.rep:
                            for rrset in qstate.return_msg.rep.rrsets:
                                rrset.entry.data_str = rrset.entry.data_str.replace(".", "-")

                    else:
                        log_info(f"Task type: {task_type}")

        qstate.ext_state[id] = MODULE_FINISHED
        return True

    qstate.ext_state[id] = MODULE_ERROR
    return True
