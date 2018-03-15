import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import lombok.Data;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.util.Collection;
import java.util.List;

/**
 *
 * Uses LetsEncrypt acme v2 with hover DNS verification to generate wildcard certs.
 *
 * Mostly lifted straight from:
 * https://github.com/shred/acme4j/blob/master/acme4j-example/src/main/java/org/shredzone/acme4j/ClientTest.java
 */
public class AcmeClient {

    private static final String LETSENCRYPT_ACME_V2_STAGING_ENDPOINT = "https://acme-staging-v02.api.letsencrypt.org/directory";
    private static final String LETSENCRYPT_ACME_V2_PROD_ENDPOINT = "https://acme-v02.api.letsencrypt.org/directory";

    //Challenge type to be used
    private static final ChallengeType CHALLENGE_TYPE = ChallengeType.DNS;      // required for wildcard certs

    // RSA key size of generated key pairs
    private static final int KEY_SIZE = 2048;

    private static final Logger LOG = LoggerFactory.getLogger(AcmeClient.class);
    private static final String HOVER_USERNAME = Preconditions.checkNotNull(System.getenv("HOVER_USERNAME"), "need HOVER_USERNAME");
    private static final String HOVER_PASSWORD = Preconditions.checkNotNull(System.getenv("HOVER_PASSWORD"), "need HOVER_PASSWORD");

    // staging vs prod
    private final Mode mode;

    // File name of the User Key Pair
    private final File USER_KEY_FILE;

    // File name of the Domain Key Pair
    private final File DOMAIN_KEY_FILE;

    // File name of the CSR
    private final File DOMAIN_CSR_FILE;

    // File name of the signed certificate
    private final File DOMAIN_CHAIN_FILE;

    /**
     * select folder to put files in based on mode
     */
    private File parent() {
        File parent = new File(mode.name());
        if (!parent.exists()) {
            parent.mkdirs();
        }
        return parent;
    }

    public AcmeClient(String mode) {
        String name = mode.toUpperCase();
        this.mode = Mode.valueOf(name);
        USER_KEY_FILE = new File(parent(), "user.key");
        DOMAIN_KEY_FILE = new File(parent(), "domain.key");
        DOMAIN_CSR_FILE = new File(parent(), "domain.csr");
        DOMAIN_CHAIN_FILE = new File(parent(), "domain-chain.crt");
    }

    private enum ChallengeType { HTTP, DNS }

    /**
     * Generates a certificate for the given domains. Also takes care for the registration
     * process.
     *
     * @param domains
     *            Domains to get a common certificate for
     */
    public void fetchCertificate(Collection<String> domains) throws IOException, AcmeException {
        // Load the user key file. If there is no key file, create a new one.
        KeyPair userKeyPair = loadOrCreateUserKeyPair();

        // Create a session for Let's Encrypt.
        // Use "acme://letsencrypt.org" for production server
        Session session = new Session(mode == Mode.STAGING ? LETSENCRYPT_ACME_V2_STAGING_ENDPOINT : LETSENCRYPT_ACME_V2_PROD_ENDPOINT);

        // Get the Account.
        // If there is no account yet, create a new one.
        Account acct = findOrRegisterAccount(session, userKeyPair);

        // Load or create a key pair for the domains. This should not be the userKeyPair!
        KeyPair domainKeyPair = loadOrCreateDomainKeyPair();

        // Order the certificate
        Order order = acct.newOrder().domains(domains).create();

        // Perform all required authorizations
        for (Authorization auth : order.getAuthorizations()) {
            authorize(auth);
        }

        // Generate a CSR for all of the domains, and sign it with the domain key pair.
        CSRBuilder csrb = new CSRBuilder();
        csrb.addDomains(domains);
        csrb.sign(domainKeyPair);

        // Write the CSR to a file, for later use.
        try (Writer out = new FileWriter(DOMAIN_CSR_FILE)) {
            csrb.write(out);
        }

        // Order the certificate
        order.execute(csrb.getEncoded());

        // Wait for the order to complete
        try {
            int attempts = 10;
            while (order.getStatus() != Status.VALID && attempts-- > 0) {
                // Did the order fail?
                if (order.getStatus() == Status.INVALID) {
                    throw new AcmeException("Order failed... Giving up.");
                }

                // Wait for a few seconds
                Thread.sleep(3000L);

                // Then update the status
                order.update();
            }
        } catch (InterruptedException ex) {
            LOG.error("interrupted", ex);
            Thread.currentThread().interrupt();
        }

        // Get the certificate
        Certificate certificate = order.getCertificate();

        LOG.info("Success! The certificate for domains " + domains + " has been generated!");
        LOG.info("Certificate URL: " + certificate.getLocation());

        // Write a combined file containing the certificate and chain.
        try (FileWriter fw = new FileWriter(DOMAIN_CHAIN_FILE)) {
            certificate.writeCertificate(fw);
            LOG.info("wrote domain chain file : " + DOMAIN_CHAIN_FILE.getAbsolutePath());
        }


        summary();
    }

    private void summary() {
        if (mode == Mode.STAGING) {
            LOG.info("woohoo! staging certs generated. ");
            LOG.info("review with: `openssl x509 -in domain-chain.crt -text`");
            LOG.info("if all looks good, re-run with --mode prod");
        } else {
            LOG.info("Production certs generated!");
            LOG.info("Upload the following to your app: ");
            LOG.info("domain chain: " + DOMAIN_CHAIN_FILE.getAbsolutePath());
            LOG.info("domain key: " + DOMAIN_KEY_FILE.getAbsolutePath());
        }
    }

    /**
     * Loads a user key pair from {@value #USER_KEY_FILE}. If the file does not exist,
     * a new key pair is generated and saved.
     * <p>
     * Keep this key pair in a safe place! In a production environment, you will not be
     * able to access your account again if you should lose the key pair.
     *
     * @return User's {@link KeyPair}.
     */
    private KeyPair loadOrCreateUserKeyPair() throws IOException {
        return loadOrCreateKeyPair(USER_KEY_FILE);
    }

    /**
     * Loads a domain key pair from {@value #DOMAIN_KEY_FILE}. If the file does not exist,
     * a new key pair is generated and saved.
     *
     * @return Domain {@link KeyPair}.
     */
    private KeyPair loadOrCreateDomainKeyPair() throws IOException {
        return loadOrCreateKeyPair(DOMAIN_KEY_FILE);
    }

    private KeyPair loadOrCreateKeyPair(File file) throws IOException {
        if (file.exists()) {
            LOG.info(file.getAbsolutePath() + " exists; re-using.");
            try (FileReader fr = new FileReader(file)) {
                return KeyPairUtils.readKeyPair(fr);
            }
        } else {
            KeyPair domainKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
            try (FileWriter fw = new FileWriter(file)) {
                KeyPairUtils.writeKeyPair(domainKeyPair, fw);
                LOG.info("wrote " + file.getAbsolutePath());
            }
            return domainKeyPair;
        }
    }

    /**
     * Finds your {@link Account} at the ACME server. It will be found by your user's
     * public key. If your key is not known to the server yet, a new account will be
     * created.
     * <p>
     * This is a simple way of finding your {@link Account}. A better way is to get the
     * URL and KeyIdentifier of your new account with {@link Account#getLocation()}
     * {@link Session#getKeyIdentifier()} and store it somewhere. If you need to get
     * access to your account later, reconnect to it via
     * {@link Account#bind(Session, URI)} by using the stored location.
     *
     * @param session
     *            {@link Session} to bind with
     * @return {@link Login} that is connected to your account
     */
    private Account findOrRegisterAccount(Session session, KeyPair accountKey) throws AcmeException {
        // Ask the user to accept the TOS, if server provides us with a link.
        URI tos = session.getMetadata().getTermsOfService();
        if (tos != null) {
            acceptAgreement(tos);
        }

        Account account = new AccountBuilder()
                .agreeToTermsOfService()
                .useKeyPair(accountKey)
                .create(session);
        LOG.info("Registered a new user, URL: " + account.getLocation());

        return account;
    }

    /**
     * Authorize a domain. It will be associated with your account, so you will be able to
     * retrieve a signed certificate for the domain later.
     *
     * @param auth
     *            {@link Authorization} to perform
     */
    private void authorize(Authorization auth) throws AcmeException {
        LOG.info("Authorization for domain " + auth.getDomain());

        // The authorization is already valid. No need to process a challenge.
        if (auth.getStatus() == Status.VALID) {
            return;
        }

        // Find the desired challenge and prepare it.
        Challenge challenge = null;
        switch (CHALLENGE_TYPE) {
            case HTTP:
                challenge = httpChallenge(auth);
                break;

            case DNS:
                challenge = dnsChallenge(auth);
                break;
        }

        if (challenge == null) {
            throw new AcmeException("No challenge found");
        }

        // If the challenge is already verified, there's no need to execute it again.
        if (challenge.getStatus() == Status.VALID) {
            return;
        }

        // Now trigger the challenge.
        challenge.trigger();

        // Poll for the challenge to complete.
        try {
            int attempts = 10;
            while (challenge.getStatus() != Status.VALID && attempts-- > 0) {
                // Did the authorization fail?
                if (challenge.getStatus() == Status.INVALID) {
                    throw new AcmeException("Challenge failed... Giving up.");
                }

                // Wait for a few seconds
                Thread.sleep(3000L);

                // Then update the status
                challenge.update();
            }
        } catch (InterruptedException ex) {
            LOG.error("interrupted", ex);
            Thread.currentThread().interrupt();
        }

        // All reattempts are used up and there is still no valid authorization?
        if (challenge.getStatus() != Status.VALID) {
            throw new AcmeException("Failed to pass the challenge for domain "
                    + auth.getDomain() + ", ... Giving up.");
        }
    }

    /**
     * Prepares a HTTP challenge.
     * <p>
     * The verification of this challenge expects a file with a certain content to be
     * reachable at a given path under the domain to be tested.
     * <p>
     * This example outputs instructions that need to be executed manually. In a
     * production environment, you would rather generate this file automatically, or maybe
     * use a servlet that returns {@link Http01Challenge#getAuthorization()}.
     *
     * @param auth
     *            {@link Authorization} to find the challenge in
     * @return {@link Challenge} to verify
     */
    public Challenge httpChallenge(Authorization auth) throws AcmeException {
        // Find a single http-01 challenge
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
        if (challenge == null) {
            throw new AcmeException("Found no " + Http01Challenge.TYPE + " challenge, don't know what to do...");
        }

        // Output the challenge, wait for acknowledge...
        LOG.info("Please create a file in your web server's base directory.");
        LOG.info("It must be reachable at: http://" + auth.getDomain() + "/.well-known/acme-challenge/" + challenge.getToken());
        LOG.info("File name: " + challenge.getToken());
        String authorization = challenge.getAuthorization();
        LOG.info("Content: " + authorization);
        LOG.info("The file must not contain any leading or trailing whitespaces or line breaks!");
        LOG.info("If you're ready, dismiss the dialog...");

        StringBuilder message = new StringBuilder();
        message.append("Please create a file in your web server's base directory.\n\n");
        message.append("http://").append(auth.getDomain()).append("/.well-known/acme-challenge/").append(challenge.getToken()).append("\n\n");
        message.append("Content:\n\n");
        message.append(authorization);
//        acceptChallenge(authorization);
//        return challenge;
        throw new UnsupportedOperationException();
    }

    /**
     * Prepares a DNS challenge.
     * <p>
     * The verification of this challenge expects a TXT record with a certain content.
     * <p>
     * This example outputs instructions that need to be executed manually. In a
     * production environment, you would rather configure your DNS automatically.
     *
     * @param auth
     *            {@link Authorization} to find the challenge in
     * @return {@link Challenge} to verify
     */
    public Challenge dnsChallenge(Authorization auth) throws AcmeException {
        // Find a single dns-01 challenge
        Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE);
        if (challenge == null) {
            throw new AcmeException("Found no " + Dns01Challenge.TYPE + " challenge, don't know what to do...");
        }

        // Output the challenge, wait for acknowledge...
        LOG.info("Please create a TXT record:");
        String authDomain = auth.getDomain();
        String challengeDigest = challenge.getDigest();
        LOG.info("_acme-challenge." + authDomain + ". IN TXT " + challengeDigest);
        LOG.info("If you're ready, dismiss the dialog...");

        StringBuilder message = new StringBuilder();
        message.append("Please create a TXT record:\n\n");
        message.append("_acme-challenge." + authDomain + ". IN TXT " + challengeDigest);
        acceptChallenge(authDomain, challengeDigest);

        return challenge;
    }

    /**
     * Presents the instructions for preparing the challenge validation, and waits for
     * dismissal. If the user cancelled the dialog, an exception is thrown.
     *
     * @param auth
     *            Instructions to be shown in the dialog
     */
    public void acceptChallenge(String authDomain, String challengeDigest) throws AcmeException {
        System.out.println("... add a txt record:\n");
        String name = "_acme-challenge." + authDomain;
        String val = challengeDigest;

        createTxtRecord(authDomain, name, val);

    }

    private void createTxtRecord(String authDomain, String name, String val) {
        HoverApi api = new HoverApi(HOVER_USERNAME, HOVER_PASSWORD);
        api.login();
        HoverApi.DnsEntry dns = new HoverApi.DnsEntry();
        dns.setType("TXT");
        dns.setName(name);
        dns.setDnsTarget(val);
        api.addDnsEntry(authDomain, dns);
        LOG.info("hover txt record created...");
    }

    /**
     * Presents the user a link to the Terms of Service, and asks for confirmation. If the
     * user denies confirmation, an exception is thrown.
     *
     * @param agreement
     *            {@link URI} of the Terms of Service
     */
    public void acceptAgreement(URI agreement) throws AcmeException {
        /*int option = JOptionPane.showConfirmDialog(null,
                "Do you accept the Terms of Service?\n\n" + agreement,
                "Accept ToS",
                JOptionPane.YES_NO_OPTION);
        if (option == JOptionPane.NO_OPTION) {
            throw new AcmeException("User did not accept Terms of Service");
        }*/
    }

    /**
     * Invokes this example.
     *
     * @param args
     *            Domains to get a certificate for
     */
    public static void main(String... args) {

        Args myArgs = new Args();
        try {
            JCommander.newBuilder().addObject(myArgs).build().parse(args);
        } catch (Exception e) {
            System.err.println(e.getLocalizedMessage());
            help();
            System.exit(1);
        }

        LOG.info(myArgs.toString());
        Security.addProvider(new BouncyCastleProvider());

        try {
            AcmeClient ct = new AcmeClient(myArgs.mode);
            ct.fetchCertificate(myArgs.domains);
        } catch (Exception ex) {
            LOG.error("Failed to get a certificate for domains " + myArgs.domains, ex);
        }
    }

    private static void help() {
        System.err.println("Usage: \n" +
                "AcmeClient --mode staging --domain *.foo.org\n\n" +
                "or with gradle:\n ./gradlew run -PappArgs=\"['--domain','*.foo.org','--mode','staging']\" \n");
    }

    @Data
    public static final class Args {
        @Parameter(names = {"--mode", "-m"}, description = "staging|prod")
        private String mode;

        @Parameter(names = {"--domain", "-d"}, description = "domain to request cert for (you can repeat this arg multiple times)", required = true)
        private List<String> domains = Lists.newArrayList();

        @Parameter(names = {"--help", "-h"}, help = true)
        private boolean help;
    }

    enum Mode {
        PROD, STAGING;
    }
}
