/*******************************************************************************

    Contains unittest functions used for vtable checks of the D.

    Note: This is not part of Stellar SCP code.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

#include "scp/SCP.h"
#include "scp/SCPDriver.h"
#include "xdr/Stellar-SCP.h"

using namespace stellar;

/// Approach the vtable and return the number of virtual methods.
template <class T>
unsigned long getVirtualMethodCount(T& t)
{
    long **vtable = (long **)&t;
    unsigned long idx;
    for (idx = 0; vtable[0][idx] != 0; idx++);
    return idx;
}

/// Class for use only in tests.
/// Because SCPDriver is an interface, an inherited class is required.
class VTSCPDriver : public SCPDriver
{
  public:
    SCP mSCP;

    VTSCPDriver(NodeID const& nodeID, SCPQuorumSet const& qSetLocal, bool isValidator = true)
        : mSCP(*this, nodeID, isValidator, qSetLocal)
    {
    }

    void
    signEnvelope(SCPEnvelope&) override
    {
    }

    SCPQuorumSetPtr
    getQSet(Hash const& qSetHash) override
    {
        return SCPQuorumSetPtr();
    }

    void
    emitEnvelope(SCPEnvelope const& envelope) override
    {
    }

    SCPDriver::ValidationLevel
    validateValue(uint64 slotIndex, Value const& value, bool nomination) override
    {
        return SCPDriver::kFullyValidatedValue;
    }

    Value
    extractValidValue(uint64 slotIndex, Value const& value)
    {
        return Value();
    }

    std::string
    getValueString(Value const& v) const
    {
        return "";
    }

    std::string
    toStrKey(PublicKey const& pk, bool fullKey = true) const
    {
        return "";
    }

    std::string
    toShortString(PublicKey const& pk) const
    {
        return "";
    }

    uint64
    computeHashNode(uint64 slotIndex, Value const& prev, bool isPriority, int32_t roundNumber, NodeID const& nodeID)
    {
        return 0L;
    }

    uint64
    computeValueHash(uint64 slotIndex, Value const& prev, int32_t roundNumber, Value const& value)
    {
        return 0L;
    }

    Value
    combineCandidates(uint64 slotIndex, std::set<Value> const& candidates)
    {
        return Value();
    }

    void
    setupTimer(uint64 slotIndex, int timerID, std::chrono::milliseconds timeout, std::function<void()>* cb)
    {
    }

    std::chrono::milliseconds
    computeTimeout(uint32 roundNumber)
    {
        std::chrono::milliseconds(100);
    }

    void
    valueExternalized(uint64 slotIndex, Value const& value)
    {
    }

    void
    nominatingValue(uint64 slotIndex, Value const& value)
    {
    }

    void
    updatedCandidateValue(uint64 slotIndex, Value const& value)
    {
    }

    void
    startedBallotProtocol(uint64 slotIndex, SCPBallot const& ballot)
    {
    }

    void
    acceptedBallotPrepared(uint64 slotIndex, SCPBallot const& ballot)
    {
    }

    void
    confirmedBallotPrepared(uint64 slotIndex, SCPBallot const& ballot)
    {
    }

    void
    acceptedCommit(uint64 slotIndex, SCPBallot const& ballot)
    {
    }

    void
    ballotDidHearFromQuorum(uint64 slotIndex, SCPBallot const& ballot)
    {
    }
};

/// Returns the number of virtual methods of the SCPDriver.
unsigned long getVirtualMethodCountSCPDriver ()
{
    NodeID nodeID;
    SCPQuorumSet qSet;
    VTSCPDriver scpDriver(nodeID, qSet);

    int inheritance_depth = 2;
    int default_vmcount = 2;
    int total_default_vmcount = inheritance_depth * default_vmcount;
    return getVirtualMethodCount(scpDriver) - total_default_vmcount;
}


class A
{
public:
    int n1 = 1;
    void func1() { n1++; }
    virtual void vfunc1(){};
    virtual void vfunc2(){};
};

class B : public A
{
public:
    int n2 = 2;

    void func2() { n2++; }
    virtual void vfunc3(){};
    virtual void vfunc4(){};
};

int doCheckMethodPoint ()
{

    B *table = new B();
    void **pvftable = (void **)(*(long *)table);

    auto bfunc1 = &B::vfunc1;
    if ((long)reinterpret_cast<void *&>(bfunc1) != 1)
        return 1;

    auto bfunc2 = &B::vfunc2;
    if ((long)reinterpret_cast<void *&>(bfunc2) != 9)
        return 9;

    auto bfunc3 = &B::vfunc3;
    if ((long)reinterpret_cast<void *&>(bfunc3) != 17)
        return 17;

    auto bfunc4 = &B::vfunc4;
    if ((long)reinterpret_cast<void *&>(bfunc4) != 25)
        return 25;

    printf("B.vfunc1    :   %d\n", &B::vfunc1);
    printf("B.vfunc2    :   %d\n", &B::vfunc2);
    printf("B.vfunc3    :   %d\n", &B::vfunc3);
    printf("B.vfunc4    :   %d\n", &B::vfunc4);

    return 0;
}