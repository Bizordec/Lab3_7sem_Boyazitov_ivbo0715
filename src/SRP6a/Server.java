package SRP6a;

import javax.naming.InvalidNameException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class Server {
    private BigInteger N;   // big prime number, modulus
    private BigInteger g;   // generator
    private BigInteger k;   // parameter
    private BigInteger v;   // verifier
    private BigInteger A;   // client's public key
    private BigInteger b;   // server's secret value
    private BigInteger B;   // server's public key
    private BigInteger u;   // scrambler
    private BigInteger K;   // hash for session key
    private String I;       // login
    private String s;       // salt
    private Map<String, Pair<String, BigInteger>> database = new HashMap<>();

    public Server(BigInteger N, BigInteger g, BigInteger k) {
        this.N = N;
        this.g = g;
        this.k = k;
    }

    public void setCredentials(String I, String s, BigInteger v) throws InvalidNameException {
        if (!database.containsKey(I)) {
            database.put(I, new Pair<>(s, v));
        } else
            throw new InvalidNameException();
    }

    public void set_A(BigInteger A) throws IllegalAccessException {
        // A != 0
        if (A.equals(BigInteger.ZERO))
            throw new IllegalAccessException();
        else
            this.A = A;
    }

    public BigInteger gen_B() {
        // b is random
        b = new BigInteger(1024, new SecureRandom());
        // B = (k*v + g^b mod N) mod N
        B = (k.multiply(v).add(g.modPow(b, N))).mod(N);
        return B;
    }

    public void gen_u() throws IllegalAccessException {
        // u = H(A, B)
        u = SHA_256.hash(A, B);
        // u != 0
        if (u.equals(BigInteger.ZERO))
            throw new IllegalAccessException();
    }

    public String getClient_s(String I) throws IllegalAccessException {
        if (database.containsKey(I)) {
            this.I = I;
            s = database.get(this.I).first;
            v = database.get(this.I).second;
            return s;
        } else
            throw new IllegalAccessException();
    }

    public void genSessionKey() {
        // S = (A*(v^u mod N))^b mod N
        BigInteger S = A.multiply(v.modPow(u, N)).modPow(b, N);
        // K = H(S)
        K = SHA_256.hash(S);
    }

    public BigInteger test_M(BigInteger M_C) {
        // M = H(H(N) xor H(g), H(I), s, A, B, K)
        BigInteger M_S = SHA_256.hash(SHA_256.hash(N).xor(SHA_256.hash(g)), SHA_256.hash(I), s, A, B, K);
        // R = H(A, M, K)
        if (M_S.equals(M_C))
            return SHA_256.hash(A, M_S, K);
        else
            return BigInteger.ZERO;
    }

    private class Pair<A, B> {
        A first;
        B second;

        Pair(A first, B second) {
            this.first = first;
            this.second = second;
        }
    }
}

