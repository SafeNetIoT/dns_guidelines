'''
 resmod.py: This example shows how to modify the response from iterator 

 Copyright (c) 2009, Zdenek Vasicek (vasicek AT fit.vutbr.cz)
                     Marek Vavrusa  (xvavru00 AT stud.fit.vutbr.cz)

 This software is open source.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 
    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
 
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
 
    * Neither the name of the organization nor the names of its
      contributors may be used to endorse or promote products derived from this
      software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.
'''

def init(id, cfg): return True

def deinit(id): return True

def inform_super(id, qstate, superqstate, qdata): return True

def setTTL(qstate, ttl):
    """Updates return_msg TTL and the TTL of all the RRs"""
    if qstate.return_msg:
        qstate.return_msg.rep.ttl = ttl
        if (qstate.return_msg.rep):
            for i in range(0,qstate.return_msg.rep.rrset_count):
                d = qstate.return_msg.rep.rrsets[i].entry.data
                for j in range(0,d.count+d.rrsig_count):
                    d.rr_ttl[j] = ttl

def createAuthResponseIP(qstate, id):
    #create instance of DNS message (packet) with given parameters
    msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_TXT, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
    #append RR
    if (qstate.qinfo.qtype == RR_TYPE_TXT) or (qstate.qinfo.qtype == RR_TYPE_ANY):
        rl = qstate.mesh_info.reply_list
        while (rl):
            if rl.query_reply:
                q = rl.query_reply
                # The TTL of 0 is mandatory, otherwise it ends up in
                # the cache, and is returned to other IP addresses.
                msg.answer.append("%s 0 IN TXT \"%s %d (%s)\"" % (qstate.qinfo.qname_str, q.addr,q.port,q.family))
            rl = rl.next

    #set qstate.return_msg 
    if not msg.set_return_msg(qstate):
        qstate.ext_state[id] = MODULE_ERROR 
        return True

    #we don't need validation, result is valid
    qstate.return_msg.rep.security = 2

    qstate.return_rcode = RCODE_NOERROR
    qstate.ext_state[id] = MODULE_FINISHED 
    return True

def createAuthResponseSimple(qstate, id):
    #create instance of DNS message (packet) with given parameters
    msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
    #append RR
    if (qstate.qinfo.qtype == RR_TYPE_A) or (qstate.qinfo.qtype == RR_TYPE_ANY):
        msg.answer.append("%s 10 IN A 127.0.0.1" % qstate.qinfo.qname_str)
    #set qstate.return_msg 
    if not msg.set_return_msg(qstate):
        qstate.ext_state[id] = MODULE_ERROR 
        return True

    #we don't need validation, result is valid
    qstate.return_msg.rep.security = 2

    qstate.return_rcode = RCODE_NOERROR
    qstate.ext_state[id] = MODULE_FINISHED 
    return True

def operate(id, event, qstate, qdata):
    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):
        #pass the query to validator
        qstate.ext_state[id] = MODULE_WAIT_MODULE 
        return True

    if event == MODULE_EVENT_MODDONE:
        log_info("pythonmod: iterator module done")

        if not qstate.return_msg:
            qstate.ext_state[id] = MODULE_FINISHED 
            return True

        #modify the response

        qdn = qstate.qinfo.qname_str
        #log_info(qdn)
        
        '''if qdn.endswith("com"):
            #invalidate response in cache added by iterator: .nic.cz.
            #invalidateQueryInCache(qstate, qstate.return_msg.qinfo)

            #modify TTL to 10 secs and store response in cache
            #setTTL(qstate, 5)
            #if not storeQueryInCache(qstate, qstate.return_msg.qinfo, qstate.return_msg.rep, 0):
            #    qstate.ext_state[id] = MODULE_ERROR
            #    return False

            #modify TTL of response, which will be send to a) validator and then b) client
            setTTL(qstate, 10)
            qstate.return_rcode = RCODE_NOERROR'''

        setTTL(qstate, 10)
        qstate.return_rcode = RCODE_NOERROR

        qstate.ext_state[id] = MODULE_FINISHED 
        return True

        #createAuthResponseIP(qstate, id)
      
    log_err("pythonmod: bad event")
    qstate.ext_state[id] = MODULE_ERROR
    return True
