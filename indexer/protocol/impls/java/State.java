import java.math.BigInteger;
import java.util.*;

// Live indexer state — the only thing an indexer MUST keep (§3.9), and exactly
// what the canonical digest (§4) serializes. Names keyed by their raw ASCII bytes
// (charset [a-z0-9-] + structural rules, already lowercase = canonical key, §3.1).
// Names-only: votes / decorations / overflow flag removed from consensus state.
final class State {
    static final byte[] ZERO20 = new byte[20];
    static final byte[] ZERO32 = new byte[32];

    static final class NameRow {
        byte[] owner = ZERO20;
        int ownerType;                 // NOT digested (cosmetic, §3.9) — tracked only
        int st = Const.OWNED;          // OWNED/LISTED/OFFERED/RESERVED
        long leaseExpiry;
        // listing / offer
        byte[] seller = ZERO20;
        int sellerType;                // digested
        BigInteger price = BigInteger.ZERO;
        long offerExpiry;
        // reservation (reserved) OR named buyer (offered)
        byte[] buyer = ZERO20;
        BigInteger burnLeg = BigInteger.ZERO;
        BigInteger payLeg = BigInteger.ZERO;
        long reserveExpiry;
    }

    static final class Commit {
        byte[] commitment;             // 32
        long commitHeight;
        long txIndex;                  // u32 — the COMMIT's position in its block (§3.2 tuple)
        long commitTime;               // MTP at commit (COMMIT_EXPIRY window)
    }

    final Map<String, NameRow> names = new HashMap<>();
    final List<Commit> commits = new ArrayList<>();
    final Map<String, Long> muts = new HashMap<>();           // key = hex(owner) -> last_set_mutation_height

    // per-block claim scratch (NOT digested): name -> {commit_height, owner, commit tx_index}
    static final class ClaimMark { long commitHeight; byte[] owner; long commitTxIndex; }
    final Map<String, ClaimMark> claimScratch = new HashMap<>();

    void clear() {
        names.clear(); commits.clear(); muts.clear();
        claimScratch.clear();
    }

    // ---- helpers -----------------------------------------------------------

    static String nameKey(byte[] n) { return new String(n, java.nio.charset.StandardCharsets.US_ASCII); }

    void bumpMut(byte[] owner, long height) { muts.put(Hex.enc(owner), height); }

    long lastMut(byte[] owner) { Long h = muts.get(Hex.enc(owner)); return h == null ? Long.MIN_VALUE : h; }

    // owned-set of an owner, names lexicographically (raw-byte) ascending — the
    // bitmap ordering (§3.5). "owned" = the name exists in the set with this owner,
    // regardless of listed/offered (a listed/offered name keeps its bitmap position).
    List<String> ownedSetSorted(byte[] owner) {
        String oh = Hex.enc(owner);
        List<String> r = new ArrayList<>();
        for (Map.Entry<String, NameRow> e : names.entrySet())
            if (Hex.enc(e.getValue().owner).equals(oh)) r.add(e.getKey());
        r.sort(State::cmpNameKey);
        return r;
    }

    // raw-byte lexicographic comparison of two ASCII name keys.
    static int cmpNameKey(String a, String b) {
        byte[] x = a.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] y = b.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        return cmpBytes(x, y);
    }

    static int cmpBytes(byte[] x, byte[] y) {
        int n = Math.min(x.length, y.length);
        for (int i = 0; i < n; i++) {
            int d = (x[i] & 0xFF) - (y[i] & 0xFF);
            if (d != 0) return d;
        }
        return x.length - y.length;
    }
}
