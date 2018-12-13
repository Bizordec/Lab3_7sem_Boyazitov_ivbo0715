package SRP6a;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Client {
    private BigInteger N;   // big prime number, modulus
    private BigInteger g;   // generator
    private BigInteger k;   // parameter
    private BigInteger x;   // client's private key
    private BigInteger v;   // verifier
    private BigInteger a;   // client's secret value
    private BigInteger A;   // client's public key
    private BigInteger B;   // server's public key
    private BigInteger u;   // scrambler
    private BigInteger K;   // hash for session key
    private BigInteger M_C; // proof of session key
    private String I;       // login
    private String p;       // password
    private String s;       // salt

    public Client(BigInteger N, BigInteger g, BigInteger k, String I, String p) {
        this.N = N;
        this.g = g;
        this.k = k;
        this.I = I;
        this.p = p;
    }

    public void setCredentials() {
        // s is random
        s = genSalt();
        // x = H(s, p)
        x = SHA_256.hash(s, p);
        // v = g^x mod N
        v = g.modPow(x, N);
    }

    private String genSalt() {
        final int size = 10;
        final String ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
        final SecureRandom RANDOM = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < size; ++i) {
            sb.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return sb.toString();
    }

    public BigInteger gen_A() {
        // a is random
        a = new BigInteger(1024, new SecureRandom());
        // A = g^a mod N
        A = g.modPow(a, N);
        return A;
    }

    public void set_s_B(String s, BigInteger B) {
        this.s = s;
        this.B = B;
    }

    public void gen_u() throws IllegalAccessException {
        // u = H(A, B)
        u = SHA_256.hash(A, B);
        // u != 0
        if (u.equals(BigInteger.ZERO))
            throw new IllegalAccessException();
    }

    public void genSessionKey() {
        // x = H(s, p)
        x = SHA_256.hash(s, p);
        // S = (B - K*(g^x mod N))^(a+u*x)) mod N
        BigInteger S = (B.subtract(k.multiply(g.modPow(x, N)))).modPow(a.add(u.multiply(x)), N);
        // K = H(S)
        K = SHA_256.hash(S);
    }

    public BigInteger gen_M() {
        // M = H(H(N) xor H(g), H(I), s, A, B, K)
        M_C = SHA_256.hash(SHA_256.hash(N).xor(SHA_256.hash(g)), SHA_256.hash(I), s, A, B, K);
        return M_C;
    }

    public boolean compare_R(BigInteger R_S) {
        // R = H(A, M, K)
        BigInteger R_C = SHA_256.hash(A, M_C, K);
        return R_C.equals(R_S);
    }

    public String get_s() {
        return s;
    }

    public BigInteger get_v() {
        return v;
    }
}
