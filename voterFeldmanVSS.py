# same as shamirs, but no library for vss, need to implement directly to get coef for vss portion.
# shamirs uses random, and thows them away
import secrets
import hashlib
from fastecdsa import curve as fcurve
from fastecdsa.point import Point
import shamirs
import lagrange
from zksk import Secret, DLRep
from zksk.composition import OrProofStmt
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn

# required to use zksk and fastecdsa together
def fastecdsaPointToZkskCompatable(point):
    group = EcGroup(714)  # secp256k1 openssl nid
    x = point.x
    y = point.y
    # 0x04 = uncompressed EC point prefix
    encoded = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    return EcPt.from_binary(encoded, group)


curve = fcurve.secp256k1
G = curve.G # base point
q = curve.q


class Voter:
    def __init__(self, voterId, threshold, numVoters,G):
        self.voterId = voterId
        self.threshold = threshold
        self.numVoters = numVoters
        self.receivedVoteShares = {}
        self.G = G
        self.H = self.createPedersenH()

    # https://blog.sip-protocol.org/blog/pedersen-commitments-explained/ "The Generator H: Nothing Up My Sleeve"
    # https://crypto.stackexchange.com/questions/82027/is-it-possible-to-compute-the-y-coordinate-of-a-point-on-secp256k1-given-only-t for explaination of how to fit.
    def createPedersenH(self) -> Point:
        data = self.G.x.to_bytes(32, "big")
        for i in range(100):
            digest = hashlib.sha256(data + i.to_bytes()).digest()
            x_cand = int.from_bytes(digest) % curve.p
            # curve is y^2 = x^3 + 7 mod p secp256k1 same as bitcoin, very nice curve as no x^1 term.
            rhs = (pow(x_cand, 3, curve.p)  + 7) % curve.p # (x^3 + 7)^(p+1)/4
            y_cand = pow(rhs, (curve.p + 1) // 4, curve.p) # rhs^(p+1)/4 , // floor div 
            if (y_cand * y_cand) % curve.p == rhs: # if no quadratic residue https://en.wikipedia.org/wiki/Quadratic_residue
                return Point(x_cand, y_cand, curve)
        raise ValueError("H generation failed")


    def castVote(self, vote: int):
        self.vote = vote
        self.r = secrets.randbelow(q)

        # voteShares = shamirs.shares(self.r, quantity=self.numVoters, threshold=self.threshold, modulus=q)
        #https://crypto.stackexchange.com/questions/6637/understanding-feldmans-vss-with-a-simple-example
        #https://en.wikipedia.org/wiki/Verifiable_secret_sharing#Feldman.E2.80.99s_scheme
        # gen coef
        coeffs = [self.r]
        for _ in range(self.threshold - 1):
            coeffs.append(secrets.randbelow(q))

        # gen vss commitments
        vssCommitments = []
        for c in coeffs:
            vssCommitments.append(c * self.H)
        
        # create shares, should be same format as shamirs
        voteShares = []
        for i in range(self.numVoters):
            x = i + 1 # voters are zero indexed, we need 1 indexing
            y = 0
            for j, c in enumerate(coeffs): # 
                y += (pow(x, j, q) * c) % q 
            y = y % q
            voteShares.append((x, y))
        
        # Pedersen commitment as before: C = v*G + r*H
        commitment = (self.vote * G) + (self.r * self.H)
                                             
        # proof as before
        H_zk = fastecdsaPointToZkskCompatable(self.H)
        G_zk = fastecdsaPointToZkskCompatable(self.G)
        C_zk = fastecdsaPointToZkskCompatable(commitment)
        r0 = Secret(name="to pin this var")
        r0.value = Bn.from_decimal(str(self.r))

        # prove C = 0*G + r*H = C = r*H) OR C = 1*G + r*H = C - G = r*H)
        stmt_1 = DLRep(C_zk, r0 * H_zk) # 0
        stmt_2 = DLRep(C_zk - G_zk, r0 * H_zk) # 1
        stmt = OrProofStmt(stmt_1, stmt_2) 
        assert commitment == vote * G + self.r * self.H # check debug
        # https://zksk.readthedocs.io/en/latest/usage.html#composing-proofs-with-or

        if self.vote == 1: # set which branch to simulate
            stmt.subproofs[0].set_simulated()
        else:
            stmt.subproofs[1].set_simulated()
        
        proof = stmt.prove()

        return commitment, voteShares, proof, vssCommitments


    def verifyVoteProof(self, commitment, proof):
        group = EcGroup(714) # secp256k1 openssl nid
        G_zk = group.generator() # Use the native generator
        H_zk = fastecdsaPointToZkskCompatable(self.H)
        C_zk = fastecdsaPointToZkskCompatable(commitment)

        r_secret = Secret(name="to pin this var") # symbolic R
        
        stmt_1 = DLRep(C_zk, r_secret * H_zk)
        stmt_2 = DLRep(C_zk - G_zk, r_secret * H_zk)
        stmt = OrProofStmt(stmt_1, stmt_2) 
        
        return stmt.verify(proof)

    def verifyShare(self, share, PublicVSSCommitments):
        x, y = share 
        lhs = y * self.H

        # Feldman VSS Verification: 
        # g^y ==  product of (Commitmentj)^(x^j)
        rhs = PublicVSSCommitments[0] 
        for i in range(1, len(PublicVSSCommitments)):
            rhs = rhs + (pow(x, i, q) * PublicVSSCommitments[i])
            
        return lhs == rhs

    def receiveShareAndVerify(self, senderId, share, proof, pedersenCommit, vssCommits):
        # ensure 1 share per sender
        if senderId not in self.receivedVoteShares:

            if not self.verifyVoteProof(pedersenCommit, proof):
                print(f"Complaint by voter {self.voterId} for Voter {senderId}: invalid proof")
            #else:
               # print(f"No complaint by {self.voterId} for Voter {senderId} proof")
                

            if not self.verifyShare(share, vssCommits):
                print(f"Complaint: Voter {senderId} invalid VSS share")
                

            self.receivedVoteShares[senderId] = share
    
    def getAggregateShare(self):
        #sum all received shares to create a share of the total R
        total_y = 0
        my_x = self.voterId + 1 # Each voter uses their id + 1 as their share x-coordinate
        
        for senderId, shard in self.receivedVoteShares.items():
            total_y = (total_y + shard[1]) % q # uses homomorphic properity of shards
            
        return (my_x, total_y)

    def tally(self, publicCommitments, aggregate_shards):
        # sum commitments
        Ctotal = publicCommitments[0]
        for i in range(1, len(publicCommitments)):
            Ctotal = Ctotal + publicCommitments[i]

        # 2. Reconstruct Total R from the aggregate shares published by all voters
        # code from inside shamirs shards, as aggrergate are no longer share objects
        totalR = lagrange.interpolate(aggregate_shards, modulus=q)

        # 3. Solve for V_total: V_total*G = C_total - (totalR * H)
        VtotalG = Ctotal + ( (q - totalR) * self.H )

        # Find the resulting number of votes that would result in sum.
        for potentialOutcome in range(self.numVoters + 1):
            if (potentialOutcome * G) == VtotalG:
                return potentialOutcome

numVoters = 5
threshold = 3  # or numVoters/2 + 1
voters = []
for i in range(numVoters):
    voters.append(Voter(i, threshold, numVoters, G))

votes = [1, 1, 1, 0, 0] # Sum should be 3
publicCommitments = [] # for bulitin Board
proofs = []
vssCommitsBulitin = [] # public board

# Step 1: voting, publishing proofs
for i, v in enumerate(votes):
    comm, shards, proof, usersVssCommits = voters[i].castVote(v)
    publicCommitments.append(comm)
    proofs.append(proof) # published to the board
    vssCommitsBulitin.append(usersVssCommits)


# Step 2: private distribution and verificaion of distributions
# This would happen over a secure channel directly between voters (RSA)
    for destID in range(numVoters):
        voters[destID].receiveShareAndVerify(i, shards[destID], proofs[i], publicCommitments[i], vssCommitsBulitin[i]) # pass whole bulitin

# Step 3: each voter computes personal aggergate for publication.
# No voter will be able to tell how another voter voted without collusion up to the threshold
allAggregateShards = [v.getAggregateShare() for v in voters]

# Step 4: tally all aggragate shards
# Each member can do this individiually to verify result for themself.
# Aggeregate Shards would be shared peer to peer in secure channels (RSA)
for i,voter in enumerate(voters):
    print(f"Voter {i} concludes: {voter.tally(publicCommitments, allAggregateShards)}/{numVoters}")
print(f"Result should be: {sum(votes)}/{numVoters}")