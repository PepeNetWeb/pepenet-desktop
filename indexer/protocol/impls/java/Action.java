import java.math.BigInteger;

// A decoded protocol action (§2). Grab-bag of per-opcode fields; only the fields
// for `op` are populated. Carrier value (rent/burn) lives on the TxOut.
final class Action {
    int op;

    // COMMIT
    byte[] commitment;      // 32

    // CLAIM (salt+name) / SELL / RESERVE / SETTLE / PAY / SELL_TO share `name`
    byte[] salt;            // 32
    byte[] name;

    // RENEW / RELEASE / TRANSFER bitmap
    int renewMode;          // 0=all, 1=all-safe, 2=selective (RENEW only)
    boolean selective;      // TRANSFER selective?
    long anchor;            // 5-byte height anchor
    byte[] flags;           // bitmap bytes

    // TRANSFER
    byte[] tTarget;         // 20

    // SELL / SELL_TO
    BigInteger price;       // u64
    long window;            // u32 (SELL)
    byte[] buyer;           // 20 (SELL_TO)

    // AS
    int asIndex;

    // TRADE
    int idxA, idxB;
    byte[] nameA, nameB;
}
