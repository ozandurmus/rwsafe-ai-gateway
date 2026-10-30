package io.rwsafe.control.support;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;

/**
 * The leak probe's synthetic estate (SR-PRIV-2): Turkish identifiers with valid checksums, Turkish mobile numbers, a
 * payment card, a secret shape, Turkish names, directory logins, e-mail addresses, domain accounts, host names, group
 * names and documentation-range addresses. Everything is built at runtime from a fresh seed (AGENTS.md 4.5); nothing
 * here is a real identifier, and no value leaves the test: the probe holds digests only.
 */
public final class Canaries {

    public static final String TCKN = "TCKN";
    public static final String TR_IBAN = "TR_IBAN";
    public static final String TR_MOBILE = "TR_MOBILE";
    public static final String PAYMENT_CARD = "PAYMENT_CARD";
    public static final String SECRET_SHAPE = "SECRET_SHAPE";
    public static final String TURKISH_NAME = "TURKISH_NAME";
    public static final String DIRECTORY_LOGIN = "DIRECTORY_LOGIN";
    public static final String CLAIM_USER = "IDENTITY_CLAIM_USER";
    public static final String EMAIL = "EMAIL";
    public static final String DOMAIN_ACCOUNT = "DOMAIN_ACCOUNT";
    public static final String HOST_NAME = "HOST_NAME";
    public static final String GROUP_NAME = "GROUP_NAME";
    public static final String IPV4 = "IPV4_ADDRESS";

    // Public name lists (MASKING_AND_PRIVACY B2 layer 4 plans a committed dictionary of the same kind); no estate data.
    private static final String[] GIVEN = {"Şükrü", "Gülşen", "Çağla", "Öykü", "Ferhunde", "Müjgan", "Tuğrul", "Nurşen"};
    private static final String[] FAMILY = {"Öztürk", "Kılıçarslan", "Çelikkaya", "Şahinoğlu", "Gümüşdere", "Karaağaç"};

    /** One synthetic person: the display name and the ASCII login a directory would hold. */
    public record Person(String given, String family, String login) {

        public String displayName() {
            return given + " " + family;
        }
    }

    public final List<String> tckns = new ArrayList<>();
    public final List<String> ibans = new ArrayList<>();
    public final List<String> mobiles = new ArrayList<>();
    public final String card;
    public final String secret;
    /** Directory users of the walk: two security admins, an officer, a viewer and the masked user. */
    public final Person admin;
    public final Person adminTwo;
    public final Person officer;
    public final Person viewer;
    public final Person masked;
    /** People who appear only as identity claims in verdict events. */
    public final List<Person> claimants = new ArrayList<>();
    public final String realm;
    public final String mailDomain;
    public final List<String> hosts = new ArrayList<>();
    public final List<String> groups = new ArrayList<>();
    public final List<String> addresses = new ArrayList<>();
    public final String signingKeyId;
    private final LeakProbe probe = new LeakProbe();

    public Canaries() {
        long seed = new SecureRandom().nextLong();
        Random r = new Random(seed);
        for (int i = 0; i < 2; i++) {
            tckns.add(Synthetic.tckn(r.nextLong()));
            ibans.add(Synthetic.iban(r.nextLong()));
            mobiles.add(mobile(r));
        }
        card = Synthetic.card(r.nextLong());
        secret = Synthetic.githubToken();
        List<Person> people = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            String given = GIVEN[(int) Math.floorMod(seed + i, (long) GIVEN.length)];
            String family = FAMILY[(int) Math.floorMod(seed / 7 + i * 5L, (long) FAMILY.length)];
            people.add(new Person(given, family, fold(given) + "." + fold(family) + letters(r, 3)));
        }
        admin = people.get(0);
        adminTwo = people.get(1);
        officer = people.get(2);
        viewer = people.get(3);
        masked = people.get(4);
        claimants.add(people.get(5));
        claimants.add(people.get(6));
        realm = "SYN" + letters(r, 5).toUpperCase(Locale.ROOT);
        mailDomain = "corp-" + letters(r, 6) + ".test";
        for (int i = 0; i < 2; i++) {
            hosts.add("srv-" + letters(r, 6) + "-" + (10 + r.nextInt(90)));
            groups.add("grp-" + letters(r, 6) + "-ops");
        }
        addresses.add("198.51.100." + (1 + r.nextInt(254)));
        addresses.add("203.0.113." + (1 + r.nextInt(254)));
        signingKeyId = hosts.get(1) + "-signing";

        tckns.forEach(v -> probe.canary(TCKN, v));
        for (String iban : ibans) {
            probe.canary(TR_IBAN, iban);
        }
        for (String m : mobiles) {
            probe.canary(TR_MOBILE, m);
            probe.canary(TR_MOBILE, m.substring(1));
            probe.canary(TR_MOBILE, "9" + m);
        }
        probe.canary(PAYMENT_CARD, card);
        probe.canary(SECRET_SHAPE, secret);
        for (Person p : people) {
            for (String name : List.of(p.given(), p.family(), fold(p.given()), fold(p.family()))) {
                probe.canary(TURKISH_NAME, name);
            }
        }
        for (Person p : List.of(admin, adminTwo, officer, viewer, masked)) {
            probe.canary(DIRECTORY_LOGIN, p.login());
        }
        for (Person p : claimants) {
            probe.canary(CLAIM_USER, p.login());
            probe.canary(EMAIL, email(p));
            probe.canary(DOMAIN_ACCOUNT, domainAccount(p));
        }
        for (String h : hosts) {
            probe.canary(HOST_NAME, h);
            probe.canary(HOST_NAME, h.substring(4, 10));
            probe.canary(HOST_NAME, h + "." + mailDomain);
        }
        for (String g : groups) {
            probe.canary(GROUP_NAME, g);
            probe.canary(GROUP_NAME, g.substring(4, 10));
        }
        for (String a : addresses) {
            probe.canary(IPV4, a);
            probe.canary(IPV4, a.substring(0, a.lastIndexOf('.')));
        }
        probe.canary(HOST_NAME, mailDomain);
    }

    public LeakProbe probe() {
        return probe;
    }

    public String email(Person p) {
        return p.login() + "@" + mailDomain;
    }

    public String domainAccount(Person p) {
        return realm + "\\" + p.login();
    }

    /**
     * The estate dictionary the PO would supply (MASKING_AND_PRIVACY B2 layer 3): host names, their FQDNs, the mail
     * domain and the directory groups.
     */
    public String estateDictionary() {
        StringBuilder b = new StringBuilder("# synthetic estate of the leak probe\n");
        for (String h : hosts) {
            b.append(h).append('\n').append(h).append('.').append(mailDomain).append('\n');
        }
        groups.forEach(g -> b.append(g).append('\n'));
        return b.append(mailDomain).append('\n').toString();
    }

    /** A Turkish mobile number in the national form: 0, 5, then nine digits. */
    private static String mobile(Random r) {
        StringBuilder b = new StringBuilder("05").append(3 + r.nextInt(3));
        for (int i = 0; i < 8; i++) {
            b.append(r.nextInt(10));
        }
        return b.toString();
    }

    private static String letters(Random r, int n) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < n; i++) {
            b.append((char) ('a' + r.nextInt(26)));
        }
        return b.toString();
    }

    /** The ASCII form a directory login uses. */
    static String fold(String name) {
        StringBuilder b = new StringBuilder();
        for (char c : name.toCharArray()) {
            b.append(switch (c) {
                case 'ş', 'Ş' -> 's';
                case 'ğ', 'Ğ' -> 'g';
                case 'ü', 'Ü' -> 'u';
                case 'ö', 'Ö' -> 'o';
                case 'ç', 'Ç' -> 'c';
                case 'ı', 'İ' -> 'i';
                default -> Character.toLowerCase(c);
            });
        }
        return b.toString();
    }
}
