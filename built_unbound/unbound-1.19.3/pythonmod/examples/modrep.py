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

def createAuthResponseIP(qstate, id):
    # Create instance of DNS message (packet) with given parameters
    msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_TXT, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
    
    # Append RR
    if qstate.qinfo.qtype in [RR_TYPE_TXT, RR_TYPE_ANY]:
        rl = qstate.mesh_info.reply_list
        while rl:
            if rl.query_reply:
                q = rl.query_reply
                # The TTL of 0 is mandatory, otherwise it ends up in the cache
                msg.answer.append(f"{qstate.qinfo.qname_str} 0 IN TXT \"{q.addr} {q.port} ({q.family})\"")
            rl = rl.next

    # Set qstate.return_msg
    if not msg.set_return_msg(qstate):
        qstate.ext_state[id] = MODULE_ERROR
        return True

    # We don't need validation, result is valid
    qstate.return_msg.rep.security = 2
    qstate.return_rcode = RCODE_NOERROR
    qstate.ext_state[id] = MODULE_FINISHED
    return True

def createAuthResponseSimple(qstate, id):
    # Create instance of DNS message (packet) with given parameters
    msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
    
    # Append RR
    if qstate.qinfo.qtype in [RR_TYPE_A, RR_TYPE_ANY]:
        msg.answer.append(f"{qstate.qinfo.qname_str} 10 IN A 127.0.0.10")
        msg.answer.append(f"{qstate.qinfo.qname_str} 10 IN A 127.0.0.100")
    
    # Set qstate.return_msg
    if not msg.set_return_msg(qstate):
        qstate.ext_state[id] = MODULE_ERROR
        return True

    # We don't need validation, result is valid
    qstate.return_msg.rep.security = 2
    qstate.return_rcode = RCODE_NOERROR
    qstate.ext_state[id] = MODULE_FINISHED
    return True

# def deleteRR(qstate, id):
    # """Delete all RRs in the current response"""
    # if qstate.return_msg:
        # qstate.return_msg.rep.rrset_count = 0
        # qstate.return_msg.rep.rrsets = []
        # qstate.return_rcode = RCODE_NOERROR
        # qstate.ext_state[id] = MODULE_FINISHED
    # else:
        # qstate.ext_state[id] = MODULE_ERROR
    # return True

def addRR(qstate, id, rr_type, rr_data):
    """Add a Resource Record to the current response"""
    if not qstate.return_msg:
        qstate.ext_state[id] = MODULE_ERROR
        return False

    msg = qstate.return_msg

    # Add the specified RR to the response
    if rr_type == RR_TYPE_A:
        msg.answer.append(f"{qstate.qinfo.qname_str} 10 IN A {rr_data}")
    elif rr_type == RR_TYPE_TXT:
        msg.answer.append(f"{qstate.qinfo.qname_str} 10 IN TXT \"{rr_data}\"")
    else:
        qstate.ext_state[id] = MODULE_ERROR
        return False

    # Update the return message
    if not msg.set_return_msg(qstate):
        qstate.ext_state[id] = MODULE_ERROR
        return False

    qstate.return_msg.rep.security = 2
    qstate.return_rcode = RCODE_NOERROR
    qstate.ext_state[id] = MODULE_FINISHED
    return True

def operate(id, event, qstate, qdata):
    if event in [MODULE_EVENT_NEW, MODULE_EVENT_PASS]:
        # Pass the query to validator
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    if event == MODULE_EVENT_MODDONE:
        log_info("pythonmod: iterator module done")

        if not qstate.return_msg:
            qstate.ext_state[id] = MODULE_FINISHED
            return True

        # Example operations based on query type
        if qstate.qinfo.qtype == RR_TYPE_A:
            createAuthResponseSimple(qstate, id)
            # addRR(qstate, id, RR_TYPE_A, "192.0.2.1")
        elif qstate.qinfo.qtype == RR_TYPE_TXT:
            createAuthResponseIP(qstate, id)
        else:
            # deleteRR(qstate, id)
            # createAuthResponseSimple(qstate, id)
            qstate.return_rcode = RCODE_NOERROR
            
            qstate.ext_state[id] = MODULE_FINISHED
            
        return True

    qstate.ext_state[id] = MODULE_ERROR
    return True
